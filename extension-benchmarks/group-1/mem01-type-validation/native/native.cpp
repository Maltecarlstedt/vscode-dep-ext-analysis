// node_extension.c
#include <node_api.h>
#include <stdio.h>

// Vulnerable function: doesn't check argument types or count
napi_value ProcessUserData(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value args[2];
  
  // Get arguments
  napi_get_cb_info(env, info, &argc, args, NULL, NULL);
  
  // Missing check if we got the expected number of arguments
  
  // Get the numeric value without checking type
  double value;
  napi_get_value_double(env, args[0], &value);  // Will fail if not a number
  
  // Get string without checking type
  char buffer[256];
  size_t buffer_size = sizeof(buffer);
  size_t copied;
  // Will fail if not a string
  napi_get_value_string_utf8(env, args[1], buffer, buffer_size, &copied);  
  
  // Process data (simplified example)
  char result[356];
  sprintf(result, "%f, %s", value, buffer);
  
  // Return result to JavaScript
  napi_value return_val;
  napi_create_string_utf8(env, result, NAPI_AUTO_LENGTH, &return_val);
  
  return return_val;
}

napi_value Init(napi_env env, napi_value exports) {
  napi_status status;
  napi_value fn;
  
  status = napi_create_function(env, NULL, 0, ProcessUserData, NULL, &fn);
  if (status != napi_ok) return NULL;
  
  status = napi_set_named_property(env, exports, "processData", fn);
  if (status != napi_ok) return NULL;
  
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)