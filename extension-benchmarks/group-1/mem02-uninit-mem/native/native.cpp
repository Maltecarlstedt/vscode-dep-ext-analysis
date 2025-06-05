// memory_exposure.cpp
#include <napi.h>
#include <cstring>

// Vulnerable function that exposes uninitialized memory
Napi::Value ExposeMemory(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  
  // Get the requested buffer size
  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "Number expected for buffer size").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  
  int size = info[0].As<Napi::Number>().Int32Value();
  
  // Limit the size to not allow accidental unwanted exposures
  if (size <= 0 || size > 1024 * 2) {
    Napi::RangeError::New(env, "Stop trying to expose your memory. Limit set to 256 bytes just to see the effect.").ThrowAsJavaScriptException();
    return env.Undefined();
  }
  
  // VULNERABILITY: Allocate memory but don't initialize it
  // This memory will contain whatever was previously in that memory location
  char* buffer = new char[size];
  
  // Create a buffer that will contain uninitialized memory
  Napi::Buffer<char> result = Napi::Buffer<char>::New(
    env, 
    buffer, 
    size,
    [](Napi::Env env, char* data) {
      // Cleanup callback
      delete[] data;
    }
  );

  std::string msg = gets(buffer); 
  
  return result;
}

// Initialize the module
Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "exposeMemory"), 
              Napi::Function::New(env, ExposeMemory));
  
  return exports;
}

NODE_API_MODULE(memory_exposure, Init)