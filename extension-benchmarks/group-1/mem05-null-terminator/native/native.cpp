#include <napi.h>
#include <cstring>
#include <string>
#include <vector>

// Function with NULL terminator handling issue: assumes JavaScript strings
// are NULL-terminated when copying to C-style char arrays
Napi::Value UnsafeCopyString(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string input = info[0].As<Napi::String>();
  
  // VULNERABILITY: Not accounting for potential embedded NULL characters
  // JavaScript strings can contain NULL bytes, but C-style functions expect NULL termination
  char* buffer = new char[input.length()]; // BUG: Not allocating space for NULL terminator
  
  // VULNERABILITY: Using strcpy which relies on NULL termination
  strcpy(buffer, input.c_str());
  
  // Do some processing with the string
  std::string processedValue(buffer); // Stops at first NULL byte if present
  
  // VULNERABILITY: Memory leak - buffer is not freed if there's an early return
  if (processedValue.empty()) {
    return Napi::String::New(env, "Empty string");
  }
  
  delete[] buffer; // Cleanup
  
  return Napi::String::New(env, processedValue);
}

// Function with incorrect length calculation when NULL bytes are present
Napi::Value UnsafeStringLength(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 1 || !info[0].IsString()) {
    Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string input = info[0].As<Napi::String>();
  
  // VULNERABILITY: Using strlen which stops at the first NULL byte
  // This doesn't properly handle JavaScript strings with embedded NULL characters
  size_t length = strlen(input.c_str());
  
  return Napi::Number::New(env, static_cast<double>(length));
}

// Function with buffer overflow risk due to NULL terminator assumptions
Napi::Value UnsafeStringConcat(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();

  if (info.Length() < 2 || !info[0].IsString() || !info[1].IsString()) {
    Napi::TypeError::New(env, "Two strings expected").ThrowAsJavaScriptException();
    return env.Null();
  }

  std::string str1 = info[0].As<Napi::String>();
  std::string str2 = info[1].As<Napi::String>();
  
  // VULNERABILITY: Not accounting for NULL bytes in size calculations
  size_t len1 = strlen(str1.c_str()); // Will stop at first NULL byte
  size_t len2 = strlen(str2.c_str()); // Will stop at first NULL byte
  
  // VULNERABILITY: Buffer might be too small if string contains NULL bytes
  char* result = new char[len1 + len2 + 1]; 
  
  // VULNERABILITY: Using strcpy/strcat which rely on NULL termination
  strcpy(result, str1.c_str());
  strcat(result, str2.c_str());
  
  Napi::String returnValue = Napi::String::New(env, result);
  delete[] result;
  
  return returnValue;
}

// Export functions
Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("unsafeCopyString", Napi::Function::New(env, UnsafeCopyString));
  exports.Set("unsafeStringLength", Napi::Function::New(env, UnsafeStringLength));
  exports.Set("unsafeStringConcat", Napi::Function::New(env, UnsafeStringConcat));
  return exports;
}

NODE_API_MODULE(nullterm_addon, Init)