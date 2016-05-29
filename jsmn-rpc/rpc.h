// -------------------------------------- //
// Copyright 2014,2015 kacangbawang.com   //
// See LICENSE                            //
// -------------------------------------- //

#ifndef RPC_H
#define	RPC_H

#include <stdint.h>

#include "jsmn.h"

#ifdef	__cplusplus
"C" {
#endif

typedef enum {
    // -- These are in the range of local error codes [-32000..-32900]
    /* No error */
    WORKSTATUS_NO_ERROR = 0,
    /* Not enough tokens were provided */
    WORKSTATUS_PARSE_ERROR_NOMEM = -32000,
    /* Invalid character inside JSON string */
    WORKSTATUS_PARSE_ERROR_INVAL = -32001,
    /* The string is not a full JSON packet, more bytes expected */
    WORKSTATUS_PARSE_ERROR_PART = -32002,
    /* Outer "shell" in incoming JSON must always be an object */
    WORKSTATUS_RPC_ERROR_INVALIDOUTER = -32003,
    /* Version string must be present */
    WORKSTATUS_RPC_ERROR_INVALIDVERSION = -32004,
    /* Id, if present, must be string/number/null */
    WORKSTATUS_RPC_ERROR_INVALIDID = -32005,
    /* Method, must be present and must be a string */
    WORKSTATUS_RPC_ERROR_INVALIDMETHOD = -32006,
    /* Params, if present, must be array/object */
    WORKSTATUS_RPC_ERROR_INVALIDPARAMS = -32007,
    /* Requested RPC method is not available locally */
    WORKSTATUS_RPC_ERROR_METHODNOTFOUND = -32008,
    /* Given params for method do not match those defined locally */
    WORKSTATUS_RPC_ERROR_PARAMSMISMATCH = -32009,
    /* RPC method install failed, check name/sig/function prototype */
    WORKSTATUS_RPC_ERROR_INSTALLMETHODS = -32010,
    /* Ran out of buffer printing JSON response */
    WORKSTATUS_RPC_ERROR_OUTOFRESBUF = -32011,

    // -- These are reserved JSONRPC code values
    /* The JSON sent is not a valid Request object */
    JSONRPC_20_INVALID_REQUEST      = -32600,
    /* The method does not exist / is not available */
    JSONRPC_20_METHODNOTFOUND       = -32601,
    /* Invalid method parameters(s) */
    JSONRPC_20_INVALIDPARAMS        = -32602,
    /* Internal JSON-RPC error */
    JSONRPC_20_INTERNALERROR        = -32603,
    /* Invalid JSON was received by the server. Error while parsing JSON text */
    JSONRPC_20_PARSE_ERROR          = -32700,
            
} workstatus_t;

//rationale for prototype:
//want a form like this:
// status function(json in, json out)
//  json in: for us we need the command string + params token + other tokens (children/siblings)
// json out: ideally we'd like to return json objects, but:
//           we don't have a way of forming them
//           we don't really need to form them, because we'll immediately convert
//           to string anyways (to send back). Thus, we take in a buffer and write json to it directly
typedef workstatus_t (*rpc_method_prototype)
     (const char* const pcCommand, const jsmntok_t* const psAllToks,
       const jsmntok_t* const psParams, char* pcResponse, int iRespMaxLen);

typedef struct {
    const char* name;
    const char* sig;
    rpc_method_prototype func;
} methodtable_entry_t;

//these will be the public interface
workstatus_t    rpc_install_methods(const methodtable_entry_t* psMethods, unsigned int uiNumMethods);
workstatus_t    rpc_handle_command(const char* const pcCommand, int iCommandLen, char* pcResponse, int iRespMaxLen);
const char*     workstatus_to_string (workstatus_t eCode);

#ifdef	__cplusplus
}
#endif

#endif	/* WORK_H */

