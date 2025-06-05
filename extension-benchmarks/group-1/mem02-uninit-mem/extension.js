const vscode = require('vscode');
const nativeAddon = require('./native/build/Release/addon.node');

function activate(context) {
  let exposeMemoryCommand = vscode.commands.registerCommand(
    'memoryExposure.exposeMemory', 
    async () => {
      try {
        const sizeInput = await vscode.window.showInputBox({
          prompt: 'Enter buffer size (bytes)',
          placeHolder: 'Max limit: 256 bytes (Do less than that for safety, preferably < 16 bytes)',
        });
        
        if (!sizeInput) return;
        
        const size = parseInt(sizeInput, 10);
        if (isNaN(size)) {
          vscode.window.showErrorMessage('Enter a number');
          return;
        }
        
        // Call the native function that exposes uninitialized memory
        const buffer = nativeAddon.exposeMemory(size);
        
        // VULNERABILITY: Display the potentially sensitive memory content
        // This might include previously freed memory that could contain passwords,
        // keys, or other sensitive data

        let memoryContent = buffer.toString('hex').match(/.{1,32}/g).join('\n');
        
        
        vscode.window.showInformationMessage(`Memory preview: ${memoryContent}`);
        
        // Create a new document with the memory contents
        const document = await vscode.workspace.openTextDocument({
          content: buffer.toString('hex').match(/.{1,32}/g).join('\n')
        });
        await vscode.window.showTextDocument(document);
      } catch (error) {
        vscode.window.showErrorMessage(`Error: ${error.message}`);
      }
    }
  );
  
  context.subscriptions.push(exposeMemoryCommand);
}

function deactivate() {}

module.exports = {
  activate,
  deactivate
}