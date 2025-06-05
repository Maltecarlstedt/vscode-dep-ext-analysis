#include <napi.h>
#include <iostream>
#include <string>
#include <vector>

// Global pointer for UAF vulnerability demonstration
char* g_buffer = nullptr;

// Structure to demonstrate double-free vulnerability
struct ResourceHolder {
    void* resource;
    bool freed;

    ResourceHolder() : resource(nullptr), freed(false) {}
};

std::vector<ResourceHolder*> resource_holders;

// Use-After-Free vulnerability demonstration
Napi::Value AllocateBuffer(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // Check arguments
    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Number expected for buffer size").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Get buffer size from arguments
    int bufferSize = info[0].As<Napi::Number>().Int32Value();
    
    // Free previous buffer if exists (correct practice)
    if (g_buffer != nullptr) {
        delete[] g_buffer;
    }
    
    // Allocate new buffer
    g_buffer = new char[bufferSize];
    
    // Initialize buffer with some data
    for (int i = 0; i < bufferSize; i++) {
        g_buffer[i] = 'A' + (i % 26);
    }
    
    return Napi::String::New(env, "Buffer allocated successfully");
}

// Function that uses the buffer after it might have been freed
Napi::Value UseBuffer(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // UAF vulnerability: No check if g_buffer is nullptr or has been freed
    if (g_buffer == nullptr) {
        return Napi::String::New(env, "Buffer is null");
    }
    
    // Use the buffer (potentially after it's been freed)
    std::string result;
    for (int i = 0; i < 10; i++) {
        result += g_buffer[i];  // UAF: Could access freed memory
    }
    
    return Napi::String::New(env, result);
}

// Function that frees the buffer
Napi::Value FreeBuffer(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // Free the buffer
    if (g_buffer != nullptr) {
        delete[] g_buffer;
        // UAF vulnerability: g_buffer is not set to nullptr after freeing
        // This should be: g_buffer = nullptr;
    }
    
    return Napi::String::New(env, "Buffer freed");
}

// Double-Free vulnerability demonstration
Napi::Value AllocateResource(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // Check arguments
    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Number expected for resource ID").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    int resourceId = info[0].As<Napi::Number>().Int32Value();
    
    // Create a new resource
    ResourceHolder* holder = new ResourceHolder();
    holder->resource = malloc(100);  // Allocate some memory
    holder->freed = false;
    
    // Store it in our vector with the given ID (vulnerable if ID exceeds vector size)
    if (resourceId >= 0) {
        if (resourceId >= resource_holders.size()) {
            resource_holders.resize(resourceId + 1, nullptr);
        }
        // Potential memory leak if we're overwriting a previous allocation
        resource_holders[resourceId] = holder;
    }
    
    return Napi::Number::New(env, resourceId);
}

// Function to free a resource by ID
Napi::Value FreeResource(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // Check arguments
    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Number expected for resource ID").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    int resourceId = info[0].As<Napi::Number>().Int32Value();
    
    // Validate resourceId
    if (resourceId < 0 || resourceId >= resource_holders.size() || resource_holders[resourceId] == nullptr) {
        return Napi::Boolean::New(env, false);
    }
    
    ResourceHolder* holder = resource_holders[resourceId];
    
    // Double-free vulnerability: No check if already freed
    if (holder->resource != nullptr) {
        free(holder->resource);
        holder->resource = nullptr;
        holder->freed = true;  // Mark as freed but don't remove from vector
    }
    
    return Napi::Boolean::New(env, true);
}

// Function that can cause double-free if called twice on the same ID
Napi::Value ForceDoubleFree(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // Check arguments
    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Number expected for resource ID").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    int resourceId = info[0].As<Napi::Number>().Int32Value();
    
    // Validate resourceId
    if (resourceId < 0 || resourceId >= resource_holders.size() || resource_holders[resourceId] == nullptr) {
        return Napi::Boolean::New(env, false);
    }
    
    ResourceHolder* holder = resource_holders[resourceId];
    
    // Double-free vulnerability: Free regardless of freed status
    if (holder->resource != nullptr) {
        free(holder->resource);  // This could be a double-free if already freed
        holder->resource = nullptr;
    }
    
    return Napi::Boolean::New(env, true);
}

// Initialize module
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Export buffer-related functions (UAF vulnerability)
    exports.Set("allocateBuffer", Napi::Function::New(env, AllocateBuffer));
    exports.Set("useBuffer", Napi::Function::New(env, UseBuffer));
    exports.Set("freeBuffer", Napi::Function::New(env, FreeBuffer));
    
    // Export resource-related functions (Double-Free vulnerability)
    exports.Set("allocateResource", Napi::Function::New(env, AllocateResource));
    exports.Set("freeResource", Napi::Function::New(env, FreeResource));
    exports.Set("forceDoubleFree", Napi::Function::New(env, ForceDoubleFree));
    
    return exports;
}

NODE_API_MODULE(memory_vulnerabilities, Init)