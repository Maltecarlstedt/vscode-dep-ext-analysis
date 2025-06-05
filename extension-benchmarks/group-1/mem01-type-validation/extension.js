// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
const vscode = require('vscode');

const nativeAddon = require('./native/build/Release/addon.node');

// const path = require('path');
// const nativeAddon = require(path.join(__dirname, 'build', 'Release', 'addon.node'));

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed


function activate(context) {

  console.log('Extension "vulnerable-extension" is now active');

  // Register a command that uses the vulnerable native module
  let disposable = vscode.commands.registerCommand('typeValidation.processData', async () => {

    console.log('Command "type-validation.processData" executed');
    try {
      // Get user input
      const valueInput = await vscode.window.showInputBox({
        prompt: 'Enter a number value',
        placeHolder: 'e.g., 42'
      });
      
      const textInput = await vscode.window.showInputBox({
        prompt: 'Enter some text',
        placeHolder: 'e.g., Hello World'
      });

      // VULNERABLE: No validation before passing to native code
      // Should check if valueInput is a valid number
      const value = Number(valueInput);
      
      // Process the data using the native module
      try {
        // VULNERABILITY EXPOSURE: We don't check if inputs are valid or present
        // This directly calls the native function with missing type checks
        const result = nativeAddon.processData(value, textInput);
        vscode.window.showInformationMessage(`Result: ${result}`);
      } catch (error) {
        // Native code might crash due to invalid inputs
        vscode.window.showErrorMessage(`Native module error: ${error.message}`);
      }
    } catch (error) {
      vscode.window.showErrorMessage(`Error: ${error.message}`);
    }
  });

  context.subscriptions.push(disposable);
}

function deactivate() {}

module.exports = {
	activate,
	deactivate
}
