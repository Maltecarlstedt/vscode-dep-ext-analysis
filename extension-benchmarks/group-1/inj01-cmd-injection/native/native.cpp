#include <napi.h>
#include <stdlib.h>
#include <string>

/**
 * Execute a shell command with system() - vulnerable to command injection
 */
Napi::Value ExecuteCommand(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // Check if an argument was provided
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Wrong number of arguments").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    // Get the command from JavaScript
    std::string command = info[0].ToString();
    
    // Use popen to capture command output
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        Napi::Error::New(env, "Failed to execute command").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    // Read the output
    char buffer[128];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }
    pclose(pipe);
    
    return Napi::String::New(env, result);
}

/**
 * Execute a command that appends user input to the echo command without sanitization
 */
Napi::Value ExecuteCommandWithEcho(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // Check if an argument was provided
    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Wrong number of arguments").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    // Get the user input from JavaScript
    std::string userInput = info[0].ToString();
    
    // Concatenate the input directly to a command - vulnerable to injection
    std::string fullCommand = "echo " + userInput;
    
    // Use popen to capture command output
    FILE* pipe = popen(fullCommand.c_str(), "r");
    if (!pipe) {
        Napi::Error::New(env, "Failed to execute command").ThrowAsJavaScriptException();
        return env.Null();
    }
    
    // Read the output
    char buffer[128];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }
    pclose(pipe);
    
    return Napi::String::New(env, result);
}

/**
 * Initialize module
 */
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("executeCommand", Napi::Function::New(env, ExecuteCommand));
    exports.Set("executeCommandWithEcho", Napi::Function::New(env, ExecuteCommandWithEcho));
    return exports;
}

NODE_API_MODULE(commandinjection, Init)