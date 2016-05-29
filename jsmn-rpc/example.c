// -------------------------------------- //
// Copyright 2014,2015 kacangbawang.com   //
// See LICENSE                            //
// -------------------------------------- //

#include <stdio.h>  //printf
#include <string.h> //strlen
#include <assert.h> //asert
#include <errno.h>  //errno

#include "rpc.h"

//rpc prototype
static
workstatus_t echo(const char* const pcJSONString, const jsmntok_t* const ps_argtok,
          const jsmntok_t* const ps_alltoks, char* pcResponse, int RespMaxLen);

//rpc sig
static methodtable_entry_t test_methods[] = {
    {"echo", "(S)P", echo},
};

//rpc body
static
workstatus_t echo(const char* const pcJSONString, const jsmntok_t* const ps_argtok,
          const jsmntok_t* const ps_alltoks, char* pcResponse, int iRespMaxLen)
{
    //estimate
    const jsmntok_t* psTokEchoValue =
                &ps_alltoks[(&ps_alltoks[ps_argtok->first_child])->first_child];
    if (pcResponse && iRespMaxLen < (2 + psTokEchoValue->end - psTokEchoValue->start)) {
        return WORKSTATUS_RPC_ERROR_OUTOFRESBUF;
    }

    //do function
    //nothing

    //write retval
    if (pcResponse) {
        snprintf(pcResponse, iRespMaxLen, "\"%.*s\"", psTokEchoValue->end - psTokEchoValue->start,
                                            &pcJSONString[psTokEchoValue->start]);
    }

    //return status
    return WORKSTATUS_NO_ERROR;
}

#define MY_BUF_SIZE 2048
static char g_input[MY_BUF_SIZE];
static char g_output[MY_BUF_SIZE];

int main(int argc, char** argv) {

    workstatus_t eStatus = rpc_install_methods(test_methods, sizeof(test_methods)/sizeof(test_methods[0]));
    if(eStatus != WORKSTATUS_NO_ERROR) {
    	assert(0);
    }

	int status = fread(g_input, 1, sizeof(g_input),  stdin);
	if (status == 0) {
		fprintf(stderr, "fread(): errno=%d\n", errno);
        return 1;
    }

	//rpc
    eStatus = rpc_handle_command(g_input, strlen(g_input), g_output, MY_BUF_SIZE);
        
	//text reply?
    if(strlen(g_output) > 0) {
    	printf(">> %s\n", g_output);
    } else {
    	printf(">> no reply\n");
    }
    printf("%s\n", workstatus_to_string(eStatus));

	return 0;
}
