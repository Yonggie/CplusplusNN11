#include "Cplusplus_Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "svm.h"
#include <cmath>
#include <ctime>




const double PI = 3.1415;
const double e = 2.7182818;
const int NUM_OF_DATA = 3200;
const int maxn = NUM_OF_DATA + 5;
const int ALL_FEATURE = 15;
const int FEATURE = 14;
const int CLASSES = 2;
const int TestSetNumber = 100;
const int ClientNumber = 10;
double Data[maxn][ALL_FEATURE];

struct BayesModel {
	double GuassianMean[FEATURE + 5];
	double GuassianDeviation[FEATURE + 5];
};
//common
void SGXGetData(double data[3200][15]) {
	for (int i = 0;i < NUM_OF_DATA;i++)
		for (int j = 0;j < ALL_FEATURE;j++)
			Data[i][j] = data[i][j];
}

//SVM
void SGXInitSVMParam(svm_parameter *p) {
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
void SGXFeedSVMData(svm_problem *problem,svm_parameter *p,int start,int end,svm_node *x_sspace) {
	if (p->gamma == 0) p->gamma = 0.5;

	problem->l = start>end?start-end:end-start;
	problem->y = new double[problem->l];

	svm_node *x_space = new svm_node[(ALL_FEATURE + 1)*problem->l];//to restore feature
	problem->x = new svm_node *[problem->l]; //every X points to one sample

	int cnt = 0;
	for (int i = start;i < end;i++) {
		int before = cnt;
		for (int j = 0;j < ALL_FEATURE - 1;j++) {
			x_space[cnt].index = j;
			x_space[cnt].value = Data[i][j];
			cnt++;
		}
		x_space[cnt].index = -1;
		cnt++;
		problem->x[i-start] = &x_space[before];
		problem->y[i-start] = Data[i][ALL_FEATURE - 1];
	}
	x_sspace = x_space;
}
void SGXSVMTrain(void *model_out, void *param, void *problem, int start, int end) {
	long long t = 0;
	time(&t,NULL);
	srand((unsigned)t);
	SGXInitSVMParam((svm_parameter*)param);
	svm_node *x_space;//declared just in case.
	SGXFeedSVMData((svm_problem*)problem, (svm_parameter*)param,start,end,x_space);
	svm_model* model_in_SGX = svm_train((svm_problem*)problem, (svm_parameter*)param);
	
	

	//deep copy
	//warning: code below can only applied to 2-class classification
	svm_model* temp_model = (svm_model*)model_out;
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
			temp_model->nSV[i]=model_in_SGX->nSV[i];
		
	}

	//copy rho  /* constants in decision functions (rho[k*(k-1)/2]) */
	temp_model->rho[0] = model_in_SGX->rho[0];
	temp_model->rho[1] = model_in_SGX->rho[1];

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



//for bayes
void SGXBayesTrain(void *m,int start,int end) {
	BayesModel *model = (BayesModel*)(m);
	for (int i = 0;i < ALL_FEATURE;i++) {
		double mean = -1, deviation = -1;
		double all = 0;
		for (int j = start;j < end;j++)
			all += Data[j][i];
		mean = all / NUM_OF_DATA;
		model->GuassianMean[i] = mean;
		double temp = 0;
		for (int j = start;j < end;j++)
			temp += pow(Data[j][i] - mean, 2);

		deviation = temp / NUM_OF_DATA;
		model->GuassianDeviation[i] = deviation;
	}
}






//encryption functions

//it'll automatically increase to nearest length.
// eg, 1byte at first, then increased to 16byte; 17byte at first, then increased to 32byte
void SGXEncrypt(
	 sgx_aes_ctr_128bit_key_t *key,
	 uint8_t *text,
	uint32_t length,
	uint8_t *counter,
	uint32_t bit,
	uint8_t *result) {
	sgx_aes_ctr_encrypt(key, text, length, counter, bit, result);
}

void SGXDecrypt(
	sgx_aes_ctr_128bit_key_t *key,
	uint8_t *text, uint32_t length,
	uint8_t *counter, uint32_t bit,
	uint8_t *result) {
	sgx_aes_ctr_decrypt(key, text, length, counter, bit, result);
}

