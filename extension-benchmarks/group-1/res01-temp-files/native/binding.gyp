{
  "targets": [
    {
      "target_name": "addon",
      "sources": ["native.cpp"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "cflags_cc": ["-std=c++17"]
    }
  ]
}