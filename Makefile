all:
	g++ cmsproxy.cpp -o cmsproxy -lbp -lici -lssl -lcrypto -lpthread
