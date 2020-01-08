//decrypttion&encryption example code

//uint8_t text[] = "mother fucker, 1111111111I33can finally work you out!mother fucker, I can finally work you out!mother fucker, I can finally wor";
//printf("original data is: %s\n", text);
//uint8_t encrypted[DATA_LENGTH];
//uint8_t decrypted[DATA_LENGTH];
//SGXEncrypt(eid, &key, text, DATA_LENGTH, counter, 1, encrypted);
//SGXDecrypt(eid, &key, encrypted, DATA_LENGTH, counter, 1, decrypted);
//printf("decrypted data is: %s\n", decrypted);

//srand((unsigned)time(NULL));
//
//uint8_t text[] = "mother fucker, 1111111111I33can finally work you out!mother fucker, I can finally work you out!mother fucker, I can finally wor ";
//uint8_t counter[16];
//
////only aes-128 is supported by sgx inner lib.
//sgx_aes_ctr_128bit_key_t key;
//
//uint8_t encrypted[DATA_LENGTH];
//uint8_t decrypted[DATA_LENGTH];
//
//
////generate counter and key
//GenerateKeyAndCounter(key, counter);
//
//sgx_enclave_id_t eid;
//sgx_status_t ret = SGX_SUCCESS;
//sgx_launch_token_t token = { 0 };
//int updated = 0;
//
////create an enclave with above launch token
//ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
//if (ret != SGX_SUCCESS) {
//	printf("failed to create an enclave.\n");
//	return -1;
//}
//printf("original data is: %s\n", text);
//SGXEncrypt(eid, &key, text, DATA_LENGTH, counter, 1, encrypted);
//printf("encrypted data is: %s\n", encrypted);
//
//SGXDecrypt(eid, &key, encrypted, DATA_LENGTH, counter, 1, decrypted);
//printf("decrypted data is: %s\n", decrypted);
//
//
//if (SGX_SUCCESS != sgx_destroy_enclave(eid))
//return -1;
//
//
//return 0;



//create enclave code

//sgx_enclave_id_t eid;
//sgx_status_t ret = SGX_SUCCESS;
//sgx_launch_token_t token = { 0 };
//int updated = 0;
//
////create an enclave with above launch token
//ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
//if (ret != SGX_SUCCESS) {
//	printf("failed to create an enclave.\n");
//	return -1;
//}
//
//
//
//
//
//if (SGX_SUCCESS != sgx_destroy_enclave(eid))
//return -1;








//simulation code
/*Client temp = client[0];
loader.AssignData(temp, 0, 3200);*/

//create outside page for page inside.
//problem->l should be 3200
//int small_number = 2;
//temp.SVM_model->label = new int[2];
//temp.SVM_model->probA = new double[2];
//temp.SVM_model->probB = new double[2];   
//temp.SVM_model->nSV = new int[2];
//temp.SVM_model->rho = new double[2];
//int rn_class = 2;
//
//temp.SVM_model->sv_coef = new double*[temp.problem.l];//safety add one
//for(int i=0;i< rn_class-1;i++)
//	temp.SVM_model->sv_coef[i] = new double[temp.problem.l];
//
//int unknown_length = 20;
//temp.SVM_model->SV = new svm_node*[temp.problem.l];
//for (int i = 0;i < temp.problem.l;i++)
//	temp.SVM_model->SV[i] = new svm_node[unknown_length];

//
//SIMSVMTrain(temp.SVM_model, &temp.p, &temp.problem, 0, 3200);
//printf("you are about to dive into the function.\n");
//svm_save_model("testttt", temp.SVM_model);
//printf("you have successfully returned.\n");