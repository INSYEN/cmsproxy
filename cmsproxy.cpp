/**************************************
Copyright (c) 2015, INSYEN AG
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
***********************************/
#include <stdio.h>
#include <sys/mman.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

//#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
//#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
//#endif
#include <pthread.h>
#include <iostream>
#include <fstream>
#include <stdint.h>
//For ION
#include <bp.h>
#include <ion.h>
#include <sdr.h>

using namespace std;

typedef struct
{
    char* encapInEID; //Binding EID for encapsulated data
    char* encapOutEID; //Destination EID for encap
    char* rawInEID; //Binding EID for unencapsulated data
    char* rawOutEID; //Destination EID for decapsulated data
    X509* peerCert;
    X509* myCert;
    EVP_PKEY* pKey;
    std::string operationOrder;
    std::string csvFile;
} threadStruct;
bool isRunning=true;
int StartIon(Sdr* sdr,char* srcEid,BpSAP* bpSap)
{
	if (bp_attach() < 0)
	{
		cout<<"Can't attach to BP."<<endl;
		return 0;
	}

	if (bp_open(srcEid, bpSap) < 0)
	{
		cout<<"Can't open EID "<<srcEid<<endl;
		return 0;
	}
    *sdr=bp_get_sdr();

    if(*sdr==NULL)
    {
        cout<<"Couldn't open SDR"<<endl;
        return 0;
    }
	CHKZERO(sdr_begin_xn(*sdr));
	if (sdr_heap_depleted(*sdr))
	{
		sdr_exit_xn(*sdr);
		bp_close(*bpSap);
		cout<<"Heap depleted, quitting"<<endl;
		return 0;
	}
	sdr_exit_xn(*sdr);
	return 1;
}

int ReceiveBundle(Sdr sdr, BpSAP bpSap,char** buffer)
{
    BpDelivery	dlv;
	int		contentLength;
	ZcoReader	reader;
    unsigned int payloadLen;
    if (bp_receive(bpSap, &dlv, BP_BLOCKING) < 0)
    {
        cout<<"Couldn't receive bundle"<<endl;
        return 0;
    }
    if (dlv.result!=BpPayloadPresent)
    {
        cout<<"Bundle reception failed, exiting"<<endl;
        return 0;
    }
    CHKZERO(sdr_begin_xn(sdr));
    contentLength = zco_source_data_length(sdr,dlv.adu);
    zco_start_receiving(dlv.adu, &reader);
    *buffer = new char[contentLength];
    payloadLen = zco_receive_source(sdr, &reader, contentLength, *buffer);
    bp_release_delivery(&dlv, 1);

    sdr_end_xn(sdr);

    return payloadLen;
}
int SendBundle(char* eid,char* buffer,size_t len,Sdr sdr,BpSAP bpSap,int ttl = 2, int priority = 0, BpCustodySwitch custodySwitch = NoCustodyRequested)
{
    Object          bundlePayload;
	Object          bundleZco;
	Object          newBundle;
    BpExtendedCOS   extendedCOS = { 0, 0, 0 };

    if(len==0)
        return 0;

    sdr_begin_xn(sdr);
    bundlePayload = sdr_malloc(sdr,len);
    if(bundlePayload == NULL)
    {
        sdr_cancel_xn(sdr);
        return 0;
    }

    sdr_write(sdr,bundlePayload,buffer,len);
    bundleZco = zco_create(sdr,ZcoSdrSource,bundlePayload,0,len,ZcoOutbound,0);
    if(bundleZco == NULL)
    {
        sdr_cancel_xn(sdr);
        return 0;
    }

    int retval = bp_send(bpSap, eid, NULL, ttl, priority, custodySwitch, 0, 0, &extendedCOS, bundleZco,&newBundle);
    sdr_end_xn(sdr);

    return retval;
}

int SendBundleBio(char* eid,BIO* bio,Sdr sdr, BpSAP bpSap)
{
    if(bio==NULL)
        return 0;
    if(BIO_ctrl_pending(bio)==0)
        return 0;
    char* memPtr;

    size_t bndlSize = BIO_ctrl_pending(bio);
    BIO_get_mem_data(bio,&memPtr);
    return SendBundle(eid,memPtr,bndlSize,sdr,bpSap);
}

void* encryptedOutputModule(void* threadId)
{
    threadStruct* threadParam = (threadStruct*)threadId;
    uint8_t* bundleBuf;
    BIO* inputBio;
    BIO* operationBio;
    int flags = CMS_BINARY|CMS_NOCERTS;
    unsigned int bundleSize = 0;
    Sdr sdr;
    BpSAP bpSap;

    cout<<"Initializing server"<<endl;
    if(!StartIon(&sdr,threadParam->rawInEID,&bpSap))
    {
       cout<<"Failed to init ion"<<endl;
       isRunning=false;
    }
    STACK_OF(X509)* certStack = sk_X509_new_null();
    sk_X509_push(certStack,threadParam->peerCert);

    while(isRunning)
    {
        CMS_ContentInfo* packedContent = NULL;
        bundleBuf = 0;
        //Receive bundle
        bundleSize = ReceiveBundle(sdr,bpSap,(char**)&bundleBuf);

        if(bundleSize<=0)
        {
            isRunning=false;
            break;
        }
        inputBio=BIO_new_mem_buf(bundleBuf,bundleSize);
        //Run through CMS instructions
        operationBio = inputBio;
        for(std::string::iterator it = threadParam->operationOrder.begin();it!=threadParam->operationOrder.end();++it)
        {
            switch(*it)
            {
                case 's': //sign
                    packedContent = CMS_sign(threadParam->myCert,threadParam->pKey,NULL,operationBio,flags);
                break;
                case 'e': //Encrypt
                    //packedContent = CMS_encrypt(certStack,inputBio,EVP_aes_128_cbc(),CMS_BINARY);
                    packedContent = CMS_encrypt(certStack,operationBio,EVP_des_ede3_cbc(),flags);
                break;
                case 'c': //Compress
                    packedContent = CMS_compress(operationBio,-1,flags);
                break;

                default:
                    cout<<"Invalid operation"<<endl;
                    continue;
            }

            if(packedContent==NULL)
            {
                char* buffer=new char[1024];
                ERR_error_string(ERR_get_error(),buffer);
                cout<<"Creating CMS failed with code: "<<buffer<<endl;
                continue;
            }

            BIO_free(operationBio);
            operationBio=BIO_new(BIO_s_mem());

            if(i2d_CMS_bio(operationBio,packedContent)==0)
            {
                cout<<"Failed to create BIO for operation, finishing..."<<endl;
                break;
            }

        }

        //Now, transmit bundle
        if(SendBundleBio(threadParam->encapOutEID,operationBio,sdr,bpSap) <= 0)
        {
            cout<<"Couldn't send bundle, errno: "<<errno<<endl;
            continue;
        }

        if(inputBio)
            BIO_free(inputBio);
        if(operationBio!=inputBio)
            BIO_free(operationBio);
        delete bundleBuf;
        }
    bp_close(bpSap);
    return NULL;
}

void* encryptedInputModule(void* threadId)
{
    threadStruct* threadParam = (threadStruct*)threadId;
    CMS_ContentInfo* cmsData;
    char* buffer;
    unsigned char* outBuffer;
    unsigned int actualLen;
    BIO* operationBio;
    BIO* tmpBio;
    void* tmpPtr;
    size_t tmpSize;
    int retVal=1;
    std::string operationFlags="";
    uint8_t operationCount=0;
    STACK_OF(X509)* certStack=sk_X509_new_null();
    size_t payloadSize=0;
    bool createCSV=true;
    ofstream outFile;
    Sdr sdr;
    BpSAP bpSap;



    cout<<"Initializing client"<<endl;
    if(threadParam->csvFile==".")
    {
        createCSV=false;
        cout<<"Not creating CSV file"<<endl;
    }
    else
    {
        createCSV=true;
        outFile.open(threadParam->csvFile.c_str());
        //Print header
        outFile<<"inputLen,payloadLen,operationOrder"<<endl;
    }

    //Push certs to their relevant places
    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, threadParam->peerCert);
    sk_X509_push(certStack,threadParam->peerCert);

    if(!StartIon(&sdr,threadParam->encapInEID,&bpSap))
    {
       cout<<"Failed to init ion"<<endl;
       isRunning=false;

    }
    while(isRunning)
    {
        actualLen = ReceiveBundle(sdr,bpSap,&buffer);
        if(actualLen==0)
        {
            cout<<"Couldn't process payload data, exiting"<<endl;
            isRunning=false;
            break;
        }

        tmpBio=BIO_new_mem_buf(buffer,actualLen);

        retVal=1;
        operationFlags="";
        operationCount=0;

        while(retVal!=0)
        {
            //This is due to an idiosyncrasy of OpenSSL where memory BIOs will delete-on-read... which is dumb..
            //In other words, the d2i_cms_bio operation will erase the buffer

            tmpSize = BIO_get_mem_data(tmpBio,&tmpPtr);
            operationBio=BIO_new_mem_buf(tmpPtr,tmpSize);

            cmsData = d2i_CMS_bio(operationBio,NULL);
            if(cmsData==NULL)
            {
                cout<<"BIO invalid, passing data as-is "<<endl;
                retVal=0;
                break; //We're done processing here
            }
            else if(operationBio)
                BIO_free(operationBio);

            BIO_free(tmpBio);
            tmpBio=BIO_new(BIO_s_mem());

            switch(OBJ_obj2nid(CMS_get0_type(cmsData)))
            {
                case NID_pkcs7_signed: //Verify
                    retVal = CMS_verify(cmsData,certStack,store,NULL,tmpBio,0);
                    operationFlags+="v";
                break;
                case NID_pkcs7_encrypted: //Decrypt
                    retVal = CMS_decrypt(cmsData,threadParam->pKey,threadParam->peerCert,NULL,tmpBio,0);
                    operationFlags+="e";
                break;
                case NID_id_smime_ct_compressedData: //Decompress
                    retVal = CMS_uncompress(cmsData,NULL,tmpBio,0);
                    operationFlags+="c";
                break;
                default:
                    cout<<"no valid operation"<<endl;
                    retVal=0;
                    break;
            }
            operationCount++;
        }
        if(operationCount)
        {
            payloadSize = BIO_get_mem_data(operationBio,&outBuffer);

            if(createCSV)
                outFile<<actualLen<<","<<tmpSize<<","<<operationFlags<<endl;

            //Send bundle to endpoint
            if(SendBundle(threadParam->rawOutEID,(char*)tmpPtr,tmpSize,sdr,bpSap) <=0 )
            {
                cout<<"Bundle transmission failed"<<endl;
                continue;
            }
        }
    }
    outFile.close();
    bp_close(bpSap);
    return NULL;
}
void PrintHelp()
{
    cout<<"Usage: cmsproxy <operation mode> <local public cert> <local private key> <remote public cert> <local EID (encrypted tunnel) > <remote EID> <unencrypted listening eid> <send-to EID> [output csv file=out.csv]"<<endl;
    cout<<"operation mode syntax"<<endl;
    cout<<"n - don't use Diffie-Hellman... Must be the first in the chain"<<endl;
    cout<<"s - sign bundles before sending"<<endl;
    cout<<"e - encrypt bundles before sending"<<endl;
    cout<<"c - compress bundles before sending"<<endl;
    cout<<"These options can be combined, e.g.:"<<endl;
    cout<<"cs would compress then sign the bundle"<<endl;
    cout<<"ces would compress, encrypt, then sign"<<endl;
    cout<<"note: The output csv parameter is optional. If it is equal to \".\", no file will be generated"<<endl;

}
int main(int argc, char* argv[])
{
    std::string operationMode;
    std::string csvFile="out.csv";
    char* pubkeyPath;
    char* privcertPath;
    char* peercertPath;
    char* srcEID;
    char* destEID;
    char* outputEID;
    char* rawListeningEID;
    pthread_t inputThread;
    pthread_t outputThread;
    bool useDH = true;
    if(argc<9)
    {
        PrintHelp();
        return 0;
    }

    operationMode=argv[1];
    pubkeyPath=argv[2];
    privcertPath=argv[3];
    peercertPath=argv[4];
    srcEID=argv[5];
    destEID=argv[6];
    rawListeningEID=argv[7];
    outputEID=argv[8];

    if(argc==10)
    {
        csvFile=argv[9];
    }
    if(operationMode[0]=='n')
    {
        useDH=false;
        operationMode.erase(0,1);
    }
    cout<<"Dest eid="<<rawListeningEID<<endl;
    //Perform common init tasks
    //For OpenSSL
    cout<<"Starting openSSL"<<endl;
    OpenSSL_add_all_digests();
    OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

    BIO* bioError;
    X509* cert = NULL;
    X509* peerCert = NULL; //For DH
    EVP_PKEY* pKey = NULL;
    EVP_PKEY* peerKey = NULL;
    EVP_PKEY* peerPubKey = NULL;
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    //Open file descriptors for key
    FILE* pubKeyFp = fopen(pubkeyPath,"r");
    FILE* privKeyFp = fopen(privcertPath,"r");
    if((pubKeyFp==NULL) || (privKeyFp==NULL))
    {
        cout<<"Could not open key files "<<pubKeyFp<<" "<<privKeyFp<<endl;
        return 0;
    }
    cert = PEM_read_X509(pubKeyFp,NULL,0,NULL);
    if(cert==NULL)
    {
        cout<<"Certificate invalid, exiting"<<endl;
        return 0;
    }

    PEM_read_PrivateKey(privKeyFp,&pKey,0,NULL);
    if(pKey==NULL)
    {
        cout<<"pKey invalid, exiting"<<endl;
        return 0;
    }

    cout<<"Loading peer public certificate from "<<peercertPath<<endl;
    FILE* peerCertFp = fopen(peercertPath,"r");
    peerCert = PEM_read_X509(peerCertFp,NULL,0,NULL);
    if(peerCert==NULL)
    {
        cout<<"Couldn't load peer certificate, sorry"<<endl;
        fclose(peerCertFp);
        return 0;
    }
    fclose(peerCertFp);
    if(useDH)
    {
        size_t keyLen;
        EVP_PKEY* myKey = X509_get_pubkey (cert);
        EVP_PKEY_CTX* dhpKey =EVP_PKEY_CTX_new(pKey,NULL);
        peerPubKey = X509_get_pubkey (peerCert);
        EVP_PKEY_derive_init(dhpKey);
        EVP_PKEY_derive_set_peer(dhpKey,peerPubKey);
        EVP_PKEY_derive(dhpKey,NULL,&keyLen);

        peerKey = (EVP_PKEY*)OPENSSL_malloc(keyLen);

        if(EVP_PKEY_derive(dhpKey,(unsigned char*)peerKey,&keyLen)<0)
        {
             char* buffer=new char[1024];
            ERR_error_string(ERR_get_error(),buffer);
            cout<<"Could not perform DH, quitting "<<buffer<<endl;
            return 0;
        }

    }

    //Start threads
    threadStruct inTStruct;
    threadStruct outTStruct;
    inTStruct.encapInEID=srcEID;
    inTStruct.rawOutEID=outputEID;
    inTStruct.encapOutEID=destEID;
    inTStruct.rawInEID=rawListeningEID;
    inTStruct.myCert=cert;
    inTStruct.peerCert=peerCert;
    inTStruct.pKey=peerKey;
    inTStruct.csvFile=csvFile;
    inTStruct.operationOrder=operationMode;
    outTStruct=inTStruct;

    if(!useDH)
    {
        inTStruct.pKey=pKey;
        outTStruct.pKey=pKey;
    }

    cout<<"Starting threads "<<endl;
    pthread_create(&inputThread,NULL,encryptedInputModule,&inTStruct);
    pthread_create(&outputThread,NULL,encryptedOutputModule,&outTStruct);

    while(isRunning)
    {

    }

    return 0;
}
