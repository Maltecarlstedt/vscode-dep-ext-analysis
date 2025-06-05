#include <napi.h>
#include <vector>
#include <memory>

// Global storage for persistent references
class MemoryLeakStorage {
public:
  static std::vector<Napi::Reference<Napi::Value>> storedReferences;
  
  static size_t StoreReference(const Napi::Value& value) {
    storedReferences.push_back(Napi::Persistent(value));
    return storedReferences.size() - 1;
  }
};

std::vector<Napi::Reference<Napi::Value>> MemoryLeakStorage::storedReferences;

Napi::Value StoreFunctionReference(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  
  if (info.Length() < 1 || !info[0].IsFunction()) {
    Napi::TypeError::New(env, "Expected a function argument").ThrowAsJavaScriptException();
    return env.Null();
  }
  
  // VULNERABILITY: This reference is never freed
  size_t index = MemoryLeakStorage::StoreReference(info[0]);
  return Napi::Number::New(env, static_cast<uint32_t>(index));
}

Napi::Value LeakLargeObjects(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  
  if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsNumber()) {
    Napi::TypeError::New(env, "Expected count and size arguments").ThrowAsJavaScriptException();
    return env.Null();
  }
  
  uint32_t count = info[0].As<Napi::Number>().Uint32Value();
  uint32_t size = info[1].As<Napi::Number>().Uint32Value();
  
  // Limit values to prevent crashes
  if (count > 10000) count = 10000;
  if (size > 1024 * 1024) size = 1024 * 1024;
  
  for (uint32_t i = 0; i < count; i++) {
    try {
      Napi::ArrayBuffer buffer = Napi::ArrayBuffer::New(env, size);
      std::memset(buffer.Data(), 0x42, size);
      
      // VULNERABILITY: This reference is never freed
      MemoryLeakStorage::StoreReference(buffer);
    } catch (const std::exception& e) {
      Napi::Error::New(env, "Failed to create array buffer").ThrowAsJavaScriptException();
      return env.Null();
    }
  }
  
  return Napi::Number::New(env, count);
}

Napi::Value CallStoredFunction(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  
  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "Expected an index argument").ThrowAsJavaScriptException();
    return env.Null();
  }
  
  uint32_t index = info[0].As<Napi::Number>().Uint32Value();
  
  if (index >= MemoryLeakStorage::storedReferences.size()) {
    Napi::RangeError::New(env, "Invalid function index").ThrowAsJavaScriptException();
    return env.Null();
  }
  
  Napi::Value function = MemoryLeakStorage::storedReferences[index].Value();
  
  if (!function.IsFunction()) {
    Napi::TypeError::New(env, "Stored reference is not a function").ThrowAsJavaScriptException();
    return env.Null();
  }
  
  try {
    return function.As<Napi::Function>().Call({});
  } catch (const Napi::Error& e) {
    e.ThrowAsJavaScriptException();
    return env.Null();
  }
}

Napi::Value AttemptCleanup(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  
  if (info.Length() < 1 || !info[0].IsNumber()) {
    Napi::TypeError::New(env, "Expected a count argument").ThrowAsJavaScriptException();
    return env.Null();
  }
  
  uint32_t count = info[0].As<Napi::Number>().Uint32Value();
  uint32_t cleaned = 0;
  
  // VULNERABILITY: No check if count is valid
  for (uint32_t i = 0; i < count && i < MemoryLeakStorage::storedReferences.size(); i++) {
    if (!MemoryLeakStorage::storedReferences[i].IsEmpty()) {
      MemoryLeakStorage::storedReferences[i].Reset();
      cleaned++;
    }
  }
  
  return Napi::Number::New(env, cleaned);
}

Napi::Value GetMemoryStats(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  
  Napi::Object result = Napi::Object::New(env);
  result.Set("storedReferences", Napi::Number::New(env, static_cast<uint32_t>(MemoryLeakStorage::storedReferences.size())));
  result.Set("capacity", Napi::Number::New(env, static_cast<uint32_t>(MemoryLeakStorage::storedReferences.capacity())));
  
  return result;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set("storeFunction", Napi::Function::New(env, StoreFunctionReference));
  exports.Set("callFunction", Napi::Function::New(env, CallStoredFunction));
  exports.Set("leakObjects", Napi::Function::New(env, LeakLargeObjects));
  exports.Set("cleanup", Napi::Function::New(env, AttemptCleanup));
  exports.Set("getStats", Napi::Function::New(env, GetMemoryStats));
  
  return exports;
}

NODE_API_MODULE(memory_leak, Init)