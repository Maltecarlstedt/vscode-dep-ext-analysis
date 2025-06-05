#include <napi.h>
#include <string>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <vector>

#define TEMP_FILE_PREFIX "/tmp/vscode_extension_"

  // Function to create a temporary file with predictable name and write content to it
  // VULNERABLE: Uses predictable file name and insufficient permissions
  static Napi::Value CreateTempFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // Check if we have the correct number of arguments
    if (info.Length() < 1 || !info[0].IsString()) {
      Napi::TypeError::New(env, "Expected 1 string argument: content to write").ThrowAsJavaScriptException();
      return env.Null();
    }
    
    // Get the content string from the argument
    std::string content = info[0].As<Napi::String>().Utf8Value();
    
    // Create predictable temporary file name using PID
    // VULNERABLE: Predictable file name
    pid_t pid = getpid();
    std::string temp_file_path = std::string(TEMP_FILE_PREFIX) + std::to_string(pid) + ".txt";
    
    // Open file with insufficient permissions
    // VULNERABLE: World-readable and writable (0666)
    std::ofstream temp_file(temp_file_path.c_str());
    if (!temp_file.is_open()) {
      Napi::Error::New(env, "Failed to create temporary file").ThrowAsJavaScriptException();
      return env.Null();
    }
    
    temp_file << content;
    temp_file.close();
    
    // Set insecure permissions explicitly
    // VULNERABLE: Setting world-readable and writable permissions
    chmod(temp_file_path.c_str(), 0666);
    
    // VULNERABLE: No cleanup of temporary file
    // Should have unlink(temp_file_path.c_str()) here to be secure
    
    return Napi::String::New(env, temp_file_path);
  }
  
  // Function to find all temporary files created by this extension
  static Napi::Value FindTempFiles(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Array result = Napi::Array::New(env);
    
    DIR* dir;
    struct dirent* entry;
    
    // Open the /tmp directory
    dir = opendir("/tmp");
    if (!dir) {
      Napi::Error::New(env, "Failed to open /tmp directory").ThrowAsJavaScriptException();
      return env.Null();
    }
    
    // Look for files with our prefix
    std::string prefix = "vscode_extension_";
    uint32_t index = 0;
    
    while ((entry = readdir(dir)) != NULL) {
      std::string filename = entry->d_name;
      
      // Check if the filename starts with our prefix
      if (filename.rfind(prefix, 0) == 0) {
        result.Set(index++, Napi::String::New(env, std::string("/tmp/") + filename));
      }
    }
    
    closedir(dir);
    return result;
  }
  
  // Function to read the content of a temporary file
  static Napi::Value ReadTempFile(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    // Check if we have the correct number of arguments
    if (info.Length() < 1 || !info[0].IsString()) {
      Napi::TypeError::New(env, "Expected 1 string argument: file path").ThrowAsJavaScriptException();
      return env.Null();
    }
    
    // Get the file path from the argument
    std::string file_path = info[0].As<Napi::String>().Utf8Value();
    
    // Open the file
    std::ifstream file(file_path.c_str());
    if (!file.is_open()) {
      Napi::Error::New(env, "Failed to open file").ThrowAsJavaScriptException();
      return env.Null();
    }
    
    // Read the content
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    
    return Napi::String::New(env, buffer.str());
  }
  
  // Function to clean up all temporary files
  static Napi::Value Cleanup(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Array removed = Napi::Array::New(env);
    
    DIR* dir;
    struct dirent* entry;
    
    // Open the /tmp directory
    dir = opendir("/tmp");
    if (!dir) {
      Napi::Error::New(env, "Failed to open /tmp directory").ThrowAsJavaScriptException();
      return env.Null();
    }
    
    // Look for files with our prefix and remove them
    std::string prefix = "vscode_extension_";
    uint32_t index = 0;
    
    while ((entry = readdir(dir)) != NULL) {
      std::string filename = entry->d_name;
      
      // Check if the filename starts with our prefix
      if (filename.rfind(prefix, 0) == 0) {
        std::string full_path = std::string("/tmp/") + filename;
        
        // Remove the file
        if (unlink(full_path.c_str()) == 0) {
          removed.Set(index++, Napi::String::New(env, full_path));
        }
      }
    }
    
    closedir(dir);
    return removed;
  }

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("createTempFile", Napi::Function::New(env, CreateTempFile));
    exports.Set("findTempFiles", Napi::Function::New(env, FindTempFiles));
    exports.Set("readTempFile", Napi::Function::New(env, ReadTempFile));
    exports.Set("cleanup", Napi::Function::New(env, Cleanup));
  
  return exports;
}


// Initialize the module using the node-addon-api
NODE_API_MODULE(VulnerableAddon, Init);