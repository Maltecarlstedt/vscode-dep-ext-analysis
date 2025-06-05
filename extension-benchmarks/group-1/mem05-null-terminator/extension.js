const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const nativeAddon = require('./native/build/Release/addon.node'); 

/**
 * Activate the extension
 * @param {vscode.ExtensionContext} context 
 */
function activate(context) {
  console.log('NULL Terminator Issues extension is now active');

  // Register command to test string copy with NULL bytes
  let testCopyCommand = vscode.commands.registerCommand('null-terminator.testCopy', async () => {
    const input = await vscode.window.showInputBox({
      prompt: 'Enter a string to test (will add NULL byte in the middle)',
      placeHolder: 'Hello World'
    });

    if (input) {
      const halfway = Math.floor(input.length / 2);
      const stringWithNull = input.substring(0, halfway) + 
                             '\0' + 
                             input.substring(halfway);
      
      try {
        const result = nativeAddon.unsafeCopyString(stringWithNull);
        
         vscode.window.showInformationMessage(
          `JS concat result: ${stringWithNull}
          \nC++ concat result: ${result}`,
          { modal: true }
        );
      } catch (err) {
        vscode.window.showErrorMessage(`Error: ${err.message}`);
      }
    }
  });

  // Register command to test string length calculation with NULL bytes
  let testLengthCommand = vscode.commands.registerCommand('null-terminator.testLength', async () => {
    const input = await vscode.window.showInputBox({
      prompt: 'Enter a string to test (will add NULL byte in the middle)',
      placeHolder: 'Hello World'
    });

    if (input) {
      const halfway = Math.floor(input.length / 2);
      const stringWithNull = input.substring(0, halfway) + 
                             '\0' + 
                             input.substring(halfway);
      
      try {
        const jsLength = stringWithNull.length;
        const cppLength = nativeAddon.unsafeStringLength(stringWithNull);
        
        vscode.window.showInformationMessage(
          `JavaScript length: ${jsLength}, \nC++ calculated length: ${cppLength}`,
          { modal: true }
        );
      } catch (err) {
        vscode.window.showErrorMessage(`Error: ${err.message}`);
      }
    }
  });

  // Register command to test string concatenation with NULL bytes
  let testConcatCommand = vscode.commands.registerCommand('null-terminator.testConcat', async () => {
    const str1 = await vscode.window.showInputBox({
      prompt: 'Enter first string (will add NULL byte in the middle)',
      placeHolder: 'First'
    });

    if (!str1) return;

    const str2 = await vscode.window.showInputBox({
      prompt: 'Enter second string',
      placeHolder: 'Second'
    });

    if (str2) {
      const halfway = Math.floor(str1.length / 2);
      const str1WithNull = str1.substring(0, halfway) + 
                           '\0' + 
                           str1.substring(halfway);
      
      try {
        const jsResult = str1WithNull + str2;
        const cppResult = nativeAddon.unsafeStringConcat(str1WithNull, str2);
        
        vscode.window.showInformationMessage(
          `str1: ${str1WithNull}, ` +
          `\nstr2: ${str2}, ` +
          `\nJS concat result: ${jsResult}, ` +
          `\nC++ concat result: ${cppResult}`,
          { modal: true }
        );

      } catch (err) {
        vscode.window.showErrorMessage(`Error: ${err.message}`);
      }
    }
  });

  context.subscriptions.push(testCopyCommand);
  context.subscriptions.push(testLengthCommand);
  context.subscriptions.push(testConcatCommand);
}

function deactivate() {}

module.exports = {
  activate,
  deactivate
};