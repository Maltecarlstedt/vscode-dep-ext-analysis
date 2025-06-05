/**
 * Buffer Overflow Native Module
 * 
 * This module demonstrates common buffer overflow vulnerabilities when
 * handling JavaScript data in native code.
 */

#include <napi.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// VULNERABILITY 1: Using memcpy without bounds checking on fixed buffer
Napi::Value UnsafeMemcpy(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Buffer argument expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    Napi::Buffer<char> buffer = info[0].As<Napi::Buffer<char>>();
    char* data = buffer.Data();
    size_t length = buffer.Length();
    
    // Fixed-size buffer allocation
    char destination[256];
    
    // VULNERABILITY: No bounds checking before memcpy
    memcpy(destination, data, length); // Can overflow if length > 256
    
    // Use the buffer for some operation
    destination[length < 255 ? length : 255] = '\0';
    
    return Napi::String::New(env, destination);
}

// VULNERABILITY 2: Using strcpy with JavaScript data
Napi::Value UnsafeStrcpy(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String argument expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string inputStr = info[0].As<Napi::String>();
    const char* js_string = inputStr.c_str();
    
    // Fixed-size buffer
    char destination[100];
    
    // VULNERABILITY: No bounds checking before strcpy
    strcpy(destination, js_string); // Can overflow if js_string length > 100
    
    return Napi::String::New(env, destination);
}

// VULNERABILITY 3: Using strcat with JavaScript data
Napi::Value UnsafeStrcat(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String argument expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string inputStr = info[0].As<Napi::String>();
    const char* js_string = inputStr.c_str();
    
    // Fixed-size buffer with initial content
    char destination[100] = "Hello, ";
    
    // VULNERABILITY: No bounds checking before strcat
    strcat(destination, js_string); // Can overflow if combined length > 100
    
    return Napi::String::New(env, destination);
}

// VULNERABILITY 4: Indirect data flow with multiple operations
Napi::Value UnsafeIndirectFlow(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Buffer argument expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    Napi::Buffer<char> buffer = info[0].As<Napi::Buffer<char>>();
    char* source_data = buffer.Data();
    size_t source_length = buffer.Length();
    
    char fixed_buffer[128];
    
    // VULNERABILITY: Data flows through intermediate variables but still no bounds check
    void* intermediate = source_data;
    size_t intermediate_length = source_length;
    
    memcpy(fixed_buffer, intermediate, intermediate_length); // Can overflow
    
    return Napi::Boolean::New(env, true);
}

// VULNERABILITY 5: Malloc without space for null terminator
Napi::Value MallocTooSmall(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String argument expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string inputStr = info[0].As<Napi::String>();
    const char* input = inputStr.c_str();
    size_t length = strlen(input);
    
    // VULNERABILITY: Allocating exactly strlen(input) bytes without space for null terminator
    char* buffer = (char*)malloc(length); // Should be length + 1
    if (buffer) {
        strcpy(buffer, input); // Will overflow by 1 byte for the null terminator
        
        // Do something with buffer
        
        free(buffer);
    }
    
    return Napi::Boolean::New(env, true);
}

// SAFE CASE 1: Checking bounds before memcpy
Napi::Value SafeMemcpy(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsBuffer()) {
        Napi::TypeError::New(env, "Buffer argument expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    Napi::Buffer<char> buffer = info[0].As<Napi::Buffer<char>>();
    char* data = buffer.Data();
    size_t length = buffer.Length();
    
    char fixed_buffer[256];
    
    // Safe: Check buffer size before copying
    if (length <= sizeof(fixed_buffer)) {
        memcpy(fixed_buffer, data, length);
    } else {
        // Handle the error or truncate
        memcpy(fixed_buffer, data, sizeof(fixed_buffer));
    }
    
    return Napi::Boolean::New(env, true);
}

// SAFE CASE 2: Using strncat with proper bounds
Napi::Value SafeStrcat(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String argument expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string inputStr = info[0].As<Napi::String>();
    const char* js_string = inputStr.c_str();
    
    char destination[100] = "Hello, ";
    size_t current_length = strlen(destination);
    
    // Safe: Use strncat with proper size limit
    strncat(destination, js_string, sizeof(destination) - current_length - 1);
    
    return Napi::String::New(env, destination);
}

// SAFE CASE 3: Proper malloc with null termination space
Napi::Value SafeMalloc(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "String argument expected").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    std::string inputStr = info[0].As<Napi::String>();
    const char* input = inputStr.c_str();
    size_t length = strlen(input);
    
    // Safe: Allocate length + 1 bytes for the null terminator
    char* buffer = (char*)malloc(length + 1);
    if (buffer) {
        strcpy(buffer, input); // Now safe because we allocated enough space
        
        // Do something with buffer
        
        free(buffer);
    }
    
    return Napi::Boolean::New(env, true);
}

// Module initialization
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Export vulnerable functions
    exports.Set("unsafeMemcpy", Napi::Function::New(env, UnsafeMemcpy));
    exports.Set("unsafeStrcpy", Napi::Function::New(env, UnsafeStrcpy));
    exports.Set("unsafeStrcat", Napi::Function::New(env, UnsafeStrcat));
    exports.Set("unsafeIndirectFlow", Napi::Function::New(env, UnsafeIndirectFlow));
    exports.Set("mallocTooSmall", Napi::Function::New(env, MallocTooSmall));
    
    // Export safe functions
    exports.Set("safeMemcpy", Napi::Function::New(env, SafeMemcpy));
    exports.Set("safeStrcat", Napi::Function::New(env, SafeStrcat));
    exports.Set("safeMalloc", Napi::Function::New(env, SafeMalloc));
    
    return exports;
}

NODE_API_MODULE(bufferoverflowmodule, Init)