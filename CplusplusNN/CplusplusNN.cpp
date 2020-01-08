#include "svm.h"
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <time.h>
#include <cstdlib>
#include <algorithm>
#include <tchar.h>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "Cplusplus_Enclave_u.h"

#define ENCLAVE_FILE _T("Cplusplus_Enclave.signed.dll")
#define FILE_BUFFER_LENGTH 30000
using namespace std;



const double PI = 3.1415;
const double e = 2.7182818;
const int NUM_OF_DATA = 10000;//32000 available
const int maxn = NUM_OF_DATA + 5;
const int ALL_FEATURE = 15;
const int FEATURE = 14;
const int CLASSES = 2;
const int TestSetNumber = 100;
const int ClientNumber =  5;
const int DATA_LENGTH = 128;
double Data[maxn][ALL_FEATURE];


struct BayesModel {
	double GuassianMean[FEATURE + 5];
	double GuassianDeviation[FEATURE + 5];
};

void SIMInitSVMParam(svm_parameter *p);
void SIMFeedSVMData(svm_problem *problem, svm_parameter *p, int start, int end, svm_node *x_sspace);
void SIMSVMTrain(void *model_out, void *param, void *problem, int start, int end);
void GenerateKeyAndCounter(sgx_aes_ctr_128bit_key_t &key, uint8_t *counter);

class Client {
public:
	//common
	string option;
	string name;
	string ModelFileName;
	string EncryptedFileName;
	int HowManyData = 0;
	int start = 0;
	int end = 0;

	//bayes
	BayesModel *bayes_model=new BayesModel;

	//svm
	svm_model *SVM_model=new svm_model;
	svm_problem problem;
	svm_parameter p;
	svm_node *x_space;

	//encryt values
	uint8_t counter[16];
	uint8_t counter_origin[16];
	sgx_aes_ctr_128bit_key_t key;
	

	
	

	//for svm
	void InitSVMParam() {
		p.svm_type = C_SVC;
		p.kernel_type = RBF;
		p.degree = 3;
		p.gamma = 0.0001;
		p.coef0 = 0;
		p.nu = 0.5;
		p.cache_size = 100;
		p.C = 10;
		p.eps = 1e-5;
		p.shrinking = 0;
		p.probability = 0;
		p.nr_weight = 0;
		p.weight_label = NULL;
		p.weight = NULL;
	}
	void SetXSpace(){
		x_space = new svm_node[(ALL_FEATURE + 1)*problem.l];//to restore feature
		int cnt = 0;
		for (int i = start;i < end;i++) {
			int before = cnt;
			for (int j = 0;j < ALL_FEATURE;j++) {
				x_space[cnt].index = j;
				x_space[cnt].value = Data[i][j];
				cnt++;
			}
			x_space[cnt].index = -1;
			cnt++;
		}
	}
	void GenerateModelSpace() {
		int small_number = 2;
		SVM_model->label = new int[2];
		SVM_model->probA = new double[2];
		SVM_model->probB = new double[2];
		SVM_model->nSV = new int[2];
		SVM_model->rho = new double[2];
		int rn_class = 2;

		SVM_model->sv_coef = new double*[problem.l];//safety add one
		for (int i = 0;i < rn_class - 1;i++)
			 SVM_model->sv_coef[i] = new double[ problem.l];

		int unknown_length = 20;
		 SVM_model->SV = new svm_node*[ problem.l];
		for (int i = 0;i <  problem.l;i++)
			 SVM_model->SV[i] = new svm_node[unknown_length];
	}
	int SVMPredict(double *f) {
		svm_node feature[ALL_FEATURE];
		for (int i = 0;i < ALL_FEATURE - 1;i++) {
			feature[i].index = i;
			feature[i].value = f[i];
		}
		feature[ALL_FEATURE-1].index = -1;
		return svm_predict(this->SVM_model, feature);
	}
	//temperory useless.
	void ShowSVMFedData(int cnt){
		if (cnt > end - start) {
 			printf("there's no such many data.\n");
			return;
		}
		for (int i = 0;i < cnt;i++) {
			for (int j = 0;j < ALL_FEATURE;j++) {
				if (problem.x[i][j].index == -1) break;
				cout << setw(5) << problem.x[i][j].value << " ";
				cout << problem.y[i];
			}
			cout << endl;
		}
	}

	//for bayes
	int BayesPredict(double *feature) {
		int res = -1;
		double MaxProb = -1;

		for (int i = 0;i < CLASSES;i++) {
			double p = 1;
			for (int j = 0;j < FEATURE;j++) {
				p *= BayesGetProbability(feature[j], bayes_model->GuassianMean[i], bayes_model->GuassianDeviation[i]);
				//cout << p << endl;
			}
			//cout <<endl<<endl<< "i is " << i << ": probability is " << p << endl;
			if (p > MaxProb) {
				res = i;
				MaxProb = p;
			}
		}
		//cout << "res is " << res << endl;
		return res;
	}
	double BayesGetProbability(double x, double mean, double deviation) {
		double p = 1 / sqrt(2 * PI*deviation*deviation)*pow(e, -((x - mean)*(x - mean)) / (2 * deviation*deviation));
		return p;
	}
	
	//common
	void SetTypeName(string WhatType, string Name) {
		option = WhatType;
		name = Name;
		if(option=="SVM") ModelFileName = this->name + "-SVMModel.txt";
		else ModelFileName = this->name + "-BayesModel.txt";
		GenerateKeyAndCounter(key, counter);
		for (int i = 0;i < 16;i++)
			counter_origin[i] = counter[i];
		EncryptedFileName = "Encrypted " + ModelFileName;
		
		
	}
	void Train() {
		sgx_enclave_id_t eid;
		sgx_status_t ret = SGX_SUCCESS;
		sgx_launch_token_t token = { 0 };
		int updated = 0;

		//create an enclave with above launch token
		ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
		if (ret != SGX_SUCCESS) {
			printf("failed to create an enclave.\n");
		}
		SGXGetData(eid, Data);
		if (option == "bayes")
			SGXBayesTrain(eid, bayes_model, start, end);
		else if (option == "SVM") {
			//simulation
			/*printf("we are about to dive into simulation function.\n");
			GenerateModelSpace();
			SIMSVMTrain(SVM_model, &p, &problem, start, end);
			cout << "simulation training process is never troubled." << endl;*/

			//from sgx
			//printf("we are about to dive into sgx function.\n");
			GenerateModelSpace();
			//fuck, i should never have used p as parameter name! it's too bad!
			SGXSVMTrain(eid, SVM_model,&p,&problem, start, end);
			//cout << "training process is never troubled." << endl;
		}

		printf("congratulations, you've succeeded call the enclave.\n");
	}
	void GetData(int s, int e) {
		this->start = s;
		this->end = e;
		HowManyData = abs(s - e);
		problem.l = HowManyData;
	}
	void LoadModel() {
		//decrypte process is within.
		//step one, decrypt model and save. step two, load the model.
		if (option == "bayes") {}
		else if(option == "SVM"){
			printf("we are in load model.\n");
			string decrypt_path = "Decrypted_Model/" + this->ModelFileName;
			string encrypt_path = "Encrypted_Model/" + this->EncryptedFileName;

			sgx_enclave_id_t eid;
			sgx_status_t ret = SGX_SUCCESS;
			sgx_launch_token_t token = { 0 };
			int updated = 0;
			ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
			if (ret != SGX_SUCCESS) {
				printf("failed to create an enclave.\n");
				return;
			}
			ifstream in;
			ofstream out;
			try {
				in.open(encrypt_path.c_str(), ios::binary);
				out.open(decrypt_path.c_str());

				string encrypted_content;
				

				char temp_char;
				in >> noskipws;
				while (!in.eof()) {
					in >> temp_char;
					encrypted_content += temp_char;
				}
				string decrypted_content(encrypted_content);

				SGXEncrypt(eid, &key, (uint8_t*)encrypted_content.c_str(), encrypted_content.length(), counter_origin, 1, (uint8_t *)decrypted_content.c_str());
				int a = 100;
				out << decrypted_content;
				in.close();
				out.close();
			}
			catch (exception e) { printf("We cannot decrypt file.\n"); }
			if (SGX_SUCCESS != sgx_destroy_enclave(eid))
				return;
			
			string load_path = "Decrypted_Model/" + ModelFileName;
			this->SVM_model = svm_load_model(load_path.c_str());
		}

		
	}
	//ShowError use test set, which is extracted the last 100 of all training data.
	void ShowTestError() {
		int test_start = this->end - 100;
		int test_end = this->end;
		if (option == "bayes") {
			int cnt = 0;
			for (int i = start;i < end;i++) {
				if (BayesPredict(Data[i]) == Data[i][FEATURE])
					cnt++;
			}

			cout << "Accuracy：" << double(cnt) / abs(start - end) << endl;;
		}
		else if (option == "SVM") {
			string file_name = "Decrypted_Model/"+name + "-SVMModel.txt";;
			this->SVM_model = svm_load_model(file_name.c_str());
			printf("We are in show error function now\n\n");

			int correct = 0;
			SetXSpace();
			for (int i = start;i < end;i++) {
				int predict_value = SVMPredict(Data[i]);
				//printf("data is %lf, and the predict is %lf.\n", Data[i][ALL_FEATURE-1], predict_value);
				if (int(Data[i][ALL_FEATURE - 1]) == predict_value) {
					correct++;
				}
			}
			cout << "#correct is " << correct << endl;
			double accuracy = double(correct) / (end - start);
			cout << "accuracy is " << accuracy << endl;

			//svm_free_and_destroy_model(&temp.SVM_model); i don't know why it'll crush when calling it.
		}
	}
	
	void SaveAndEncrypt(){
		
		
		if (option == "bayes") {			
			ofstream f(ModelFileName);
			for (int i = 0;i < ALL_FEATURE;i++)
				f << bayes_model->GuassianMean[i] << " ";
			f << endl;
			for (int i = 0;i < ALL_FEATURE;i++)
				f << bayes_model->GuassianDeviation[i] << " ";
			f << endl;
		}
		else if (option == "SVM") {
			string path = "Encrypted_Model/" + ModelFileName;
			svm_save_model(path.c_str(), SVM_model);
		}

		string base_path = "Encrypted_Model/";
		//encrypt
		sgx_enclave_id_t eid;
		sgx_status_t ret = SGX_SUCCESS;
		sgx_launch_token_t token = { 0 };
		int updated = 0;
		ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
		if (ret != SGX_SUCCESS) {
			printf("failed to create an enclave.\n");
			return ;
		}
		ifstream in;
		ofstream out;
		try {

			/*uint8_t text[] = { 'm','o','t','h','e','r','f','u','c','k','e','r','r','r','r','\0' } ;
			printf("original data is: %s\n", text);
			uint8_t encrypted[17];
			uint8_t decrypted[16];
			SGXEncrypt(eid, &key, text, 17, counter, 1, encrypted);
			SGXDecrypt(eid, &key, encrypted, 16, counter, 1, decrypted);
			printf("decrypted data is: %s\n", decrypted);
*/
			
			in.open((base_path+ModelFileName).c_str(), ios::binary);			
			out.open((base_path + EncryptedFileName).c_str(), ios::binary);
			
			string file_content;
			
			char char_temp;
			in >> noskipws;
			while (!in.eof()) {
				in >> char_temp;
				file_content += char_temp;
			}		
			in.close();

			//let the length be 16
			int standard_len = file_content.length() % 16 + file_content.length();
			while (file_content.length() < standard_len)
				file_content += ' ';

			string encrypted_content(file_content);

			SGXEncrypt(eid, &key, (uint8_t*)file_content.c_str(), standard_len, counter, 1, (uint8_t *)encrypted_content.c_str());
			
			out<<encrypted_content;
			out.close();
			//string decrypted_content(encrypted_content);

			//without saving file it is ok.
			//SGXEncrypt(eid, &key, (uint8_t*)encrypted_content.c_str(), file_content.length(), counter, 1, (uint8_t *)decrypted_content.c_str());
			
			/*ifstream n;
			string n_string;
			n.open(base_path + EncryptedFileName,ios::binary);
			char temp_char1;
			n >> noskipws;
			while (!n.eof()) {
				n >> temp_char1;
				n_string += temp_char1;
			}
			
			
			SGXDecrypt(eid, &key, (uint8_t*)n_string.c_str(), standard_len,  counter_origin, 1, (uint8_t *)decrypted_content.c_str());
			int aba = 100;*/

		}
		catch (exception e) { printf("We cannot encrypt file.\n"); }
		if (SGX_SUCCESS != sgx_destroy_enclave(eid))
			return;
	}
	void Sent(){}
	void ShowLoadData() {
		for (int i = start;i < end;i++) {
			for (int j = 0;j < ALL_FEATURE;j++)
				cout << Data[i][j]<<" ";
			cout << endl;
		}
		cout << endl;
			
	}
};

//need fixing
//class Server {
//private:
//	double Accuracies[ClientNumber+1];
//	double FakeData[maxn][ALL_FEATURE];
//	string option;
//	int start = 0, end = 32000;
//
//	
//	BayesModel *model[ClientNumber+1];
//	double GetProbability(double x, double mean, double deviation) {
//		double p = 1 / sqrt(2 * PI*deviation*deviation)*pow(e, -((x - mean)*(x - mean)) / (2 * deviation*deviation));
//		return p;
//	}
//	void init_param(svm_parameter &p) {
//		p.svm_type = C_SVC;
//		p.kernel_type = RBF;
//		p.degree = 3;
//		p.gamma = 0.0001;
//		p.coef0 = 0;
//		p.nu = 0.5;
//		p.cache_size = 100;
//		p.C = 10;
//		p.eps = 1e-5;
//		p.shrinking = 1;
//		p.probability = 0;
//		p.nr_weight = 0;
//		p.weight_label = NULL;
//		p.weight = NULL;
//	}
//	void FeedSVMData(svm_problem *problem, svm_parameter &p) {
//		if (p.gamma == 0) p.gamma = 0.5;
//
//		problem->l = end - start;
//		problem->y = new double[problem->l];
//
//		svm_node *x_space = new svm_node[(ALL_FEATURE + 1)*problem->l];//to restore feature
//		problem->x = new svm_node *[problem->l]; //every X points to one sample
//
//		int cnt = 0;
//		for (int i = start;i < end;i++) {
//			int before = cnt;
//			for (int j = 0;j < ALL_FEATURE;j++) {
//				x_space[cnt].index = j;
//				x_space[cnt].value = Data[i][j];
//				cnt++;
//			}
//			x_space[cnt].index = -1;
//			cnt++;
//			problem->x[i] = &x_space[before];
//			problem->y[i] = Data[i][ALL_FEATURE - 1];
//		}
//
//	}
//public:
//	Server(string op){
//		option = op;
//		if (option == "bayes") {
//			for (int i = 0;i < ClientNumber + 1;i++)
//				model[i] = new BayesModel;
//		}
//		
//	}
//
//	void Train(){
//		sgx_enclave_id_t eid;
//		sgx_status_t ret = SGX_SUCCESS;
//		sgx_launch_token_t token = { 0 };
//		int updated = 0;
//
//		//create an enclave with above launch token
//		ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
//		if (ret != SGX_SUCCESS) {
//			printf("failed to create an enclave.\n");
//		}
//		SGXGetData(eid, Data);
//		if (option == "bayes")
//			SGXBayesTrain(eid, model[0], start, end);//too much, need fixing
//		else if (option == "SVM") {
//			//from outside
//			svm_parameter param_out;
//			init_param(param_out);
//			svm_problem problem_out;
//			FeedSVMData(&problem_out, param_out);
//
//			svm_model* temp_model = svm_train(&problem_out, &param_out);
//			cout << "type is " << temp_model->param.svm_type << endl;
//			getchar();
//
//			//from sgx
//			/*svm_parameter param;
//			svm_problem problem;
//			init_param(param);
//			int a = 100;
//			SGXSVMTrain(eid, SVM_model,&param,&problem, start, end,&a);
//			cout << "training process is never troubled." << endl;
//			//cout << SVM_model->param.svm_type << endl;
//			cout <<"result inside is "<< a << endl;
//			getchar();
//			*/
//		}
//	}
//	void Decrypt(){
//		//fetch all model and decrypt
//
//	}
//	void TestAll(){
//		if (option == "bayes") {
//			int correct[ClientNumber + 1] = { 0 };
//			for (int i = 0;i < ClientNumber + 1;i++) {
//				for (int j = 0;j < TestSetNumber;j++) {
//					int num = rand() % maxn;
//					if (BayesPredict(model[i], Data[num]) == Data[num][FEATURE])
//						correct[i]++;
//				}
//				Accuracies[i] = double(correct[i]) / TestSetNumber;
//			}
//		}
//		else if(option=="SVM"){
//			//pick random data to test.
//
//			//load svm model
//
//			//get results
//		}
//		
//
//	}
//};

class DataLoader{
public:
	double ToNum(string a) {
		double ans = 0;
		int pos = -1;
		for (int i = 0;i < a.length();i++) {
			if (a[i] == '.') {
				pos = i + 1;
				continue;
			}
			ans = ans * 10 + (a[i] - '0');
		}
		if (pos == -1) return ans;
		else return ans / pow(10, a.length() - pos);
	}
	DataLoader(string path) {
		ifstream FileIn;
		FileIn.open(path);
		if (!FileIn.is_open()) {
			cout << "cannot open the file." << endl;
		}


		string line;
		bool f = 0;
		int cnt = 0;
		while (getline(FileIn, line)) {
			if (cnt > NUM_OF_DATA) break;
			//cout << cnt << endl;
			vector<double> temp;

			int before = 0;
			for (int i = 0;i < line.length();i++) {
				if (line[i] == ',' || line[i] == '\n') {
					string sub = line.substr(before, i - before);

					temp.push_back(ToNum(sub));
					before = i + 1;
				}
			}
			temp.push_back(ToNum(line.substr(before, line.length() - before)));


			if (temp.size() < FEATURE) { cout << "data corrupted." << endl; }
			for (int i = 0;i < temp.size();i++)
				Data[cnt][i] = temp[i];
			cnt++;
		}
		cout << "data loading done. \ntotal number of data is: " << cnt << endl << endl;
	}
	void ShowData() {
		for (int i = 0;i < 10;i++) {
			for (int j = 0;j < ALL_FEATURE;j++)
				cout << Data[i][j] << " ";
			cout << endl;
		}
	}
	void AssignData(Client &c,int start,int end) {
		c.GetData(start, end);
	}
};






int main() {
	
	
	DataLoader loader("C:\\Users\\Lenovo\\Desktop\\adult_new.csv");
	//vector<Client> client(10, "SVM");
	
	Client client[ClientNumber];
	//6 clients maximum. the 7th will make sgx collapse due to memory limiation.
	string name[10] = { "1","2","3","4","5","6","7","8","9","10" };
	for (int i = 0;i < ClientNumber;i++) {
		client[i].SetTypeName("SVM", name[i]);
	}
		

	//you cannot push too much into sgx as memory in sgx is limited.
	int s = 0 ;
	int step = 500, e = s+step;
	for (int i = 0;i < ClientNumber;i++) {
		loader.AssignData(client[i], s, e);
		s = e;
		e = e + step;
		client[i].Train();
		client[i].SaveAndEncrypt();//bayes TBD.
		client[i].Sent();
	}
	//you should free(clients svm_model).
	cout << "all clients training and sending completed." << endl;
	
	
	//clients error check, we load model from saved model files.
	for (int i = 0;i < ClientNumber;i++) {
		client[i].LoadModel();
		client[i].ShowTestError();
		system("pause");
	}

	return 0;
}



//simulation functions
void SIMInitSVMParam(svm_parameter *p) {
	p->svm_type = C_SVC;
	p->kernel_type = RBF;
	p->degree = 3;
	p->gamma = 0.0001;
	p->coef0 = 0;
	p->nu = 0.5;
	p->cache_size = 100;
	p->C = 10;
	p->eps = 1e-5;
	p->shrinking = 0;
	p->probability = 0;
	p->nr_weight = 0;
	p->weight_label = NULL;
	p->weight = NULL;

}
void SIMFeedSVMData(svm_problem *problem, svm_parameter *p, int start, int end, svm_node *x_sspace) {
	if (p->gamma == 0) p->gamma = 0.5;
	int length = end - start;
	problem->l = length;
	problem->y = new double[problem->l];

	svm_node *x_space = new svm_node[(ALL_FEATURE + 1)*problem->l];//to restore feature
	problem->x = new svm_node *[problem->l]; //every X points to one sample

	int cnt = 0;
	for (int i = start;i < end ;i++) {
		int before = cnt;
		for (int j = 0;j < ALL_FEATURE - 1;j++) {
			x_space[cnt].index = j;
			x_space[cnt].value = Data[i][j];
			cnt++;
		}
		x_space[cnt].index = -1;
		cnt++;
		problem->x[i - start] = &x_space[before];
		problem->y[i - start] = Data[i][ALL_FEATURE - 1];
	}
	x_sspace = x_space;
}
void SIMSVMTrain(void *model_out, void *param, void *problem, int start, int end) {
	/*long long t = 0;
	time(&t, NULL);*/
	srand((unsigned)time(NULL));
	SIMInitSVMParam((svm_parameter*)param);
	printf("no problem in init parameter function.\n");
	svm_node *x_space = new svm_node();//declared just in case.
	SIMFeedSVMData((svm_problem*)problem, (svm_parameter*)param, start, end, x_space);
	printf("no problem in feed data function.\n");
	svm_model* temp_model = (svm_model*)model_out;
	svm_model* model_in_SGX = svm_train((svm_problem*)problem, (svm_parameter*)param);
	//printf("svm training process done, starting copying porcess\n");

	temp_model->param = model_in_SGX->param;
	temp_model->nr_class = model_in_SGX->nr_class;//k=nr_class, it's the classes number of your data.
	int k = temp_model->nr_class;
	temp_model->l = model_in_SGX->l;

	if (model_in_SGX->label)
	{
		for (int i = 0;i < k;i++)
			temp_model->label[i] = model_in_SGX->label[i];
	}
	if (model_in_SGX->probA) // regression has probA only
	{
		/* pariwise probability information */
		for (int i = 0;i < k*(k - 1) / 2;i++)
			temp_model->probA[i] = model_in_SGX->probA[i];
	}
	if (model_in_SGX->probB)
	{
		for (int i = 0;i < k*(k - 1) / 2;i++)
			temp_model->probB[i] = model_in_SGX->probB[i];
	}
	if (model_in_SGX->nSV)
	{
		for (int i = 0;i < k;i++)
			temp_model->nSV[i] = model_in_SGX->nSV[i];

	}

	//copy rho  /* constants in decision functions (rho[k*(k-1)/2]) */
	temp_model->rho[0] = model_in_SGX->rho[0];
	temp_model->rho[1] = model_in_SGX->rho[1];

	//coef is supposed to be a [k-1][l] 2d-arrary, yet it's [k-1][l-1]
	//l is the training number, which is 3200. it's 2 now.
	for (int i = 0;i < k - 1;i++)
		for (int j = 0;j < model_in_SGX->l;j++)
			temp_model->sv_coef[i][j] = model_in_SGX->sv_coef[i][j];


	for (int i = 0;i < model_in_SGX->l;i++) {
		int j = 0;
		while (model_in_SGX->SV[i][j].index != -1) {
			temp_model->SV[i][j].index = model_in_SGX->SV[i][j].index;
			temp_model->SV[i][j].value = model_in_SGX->SV[i][j].value;
			j++;
		}
		temp_model->SV[i][j].index = -1;
	}

	temp_model->free_sv = model_in_SGX->free_sv;

	model_out = temp_model;
}
void GenerateKeyAndCounter(sgx_aes_ctr_128bit_key_t &key, uint8_t *counter) {

	const unsigned char allChar[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	for (int i = 0;i < 16;i++) {
		key[i] = allChar[rand() % 63];
		counter[i] = allChar[rand() % 63];
	}
}