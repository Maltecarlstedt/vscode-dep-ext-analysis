// The module 'vscode' contains the VS Code extensibility API
const vscode = require('vscode');
const nativeAddon = require('./native/build/Release/addon.node'); 

function activate(context) {


  let processCommand = vscode.commands.registerCommand('temp-files.processSensitiveData', function () {
    try {
      // Get the active text editor
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage('No active editor found!');
        return;
      }

      // Get the document text
      const document = editor.document;
      const text = document.getText();

      // Collect some additional "sensitive" data
      const workspaceInfo = {
        folders: vscode.workspace.workspaceFolders ? 
                vscode.workspace.workspaceFolders.map(f => f.uri.fsPath) : [],
        name: vscode.workspace.name || 'unnamed',
        extensionVersion: '1.0.0'
      };

      // Convert to JSON
      const sensitiveData = JSON.stringify({
        content: text.substring(0, 1000), // Limit to first 1000 chars
        workspaceInfo: workspaceInfo,
        timestamp: new Date().toString()
      }, null, 2);

      // Use our vulnerable native module to write this data to a temp file
      const tempFilePath = nativeAddon.createTempFile(sensitiveData);
      
      // Note: The temporary file is never cleaned up here!
      
      vscode.window.showInformationMessage(`Data processed and saved to: ${tempFilePath}`);
    } catch (error) {
      vscode.window.showErrorMessage(`Error: ${error.message}`);
    }
  });

  // Register a command to demonstrate the vulnerability
  let exploitCommand = vscode.commands.registerCommand('temp-files.demonstrateVulnerability', async function () {
    try {
      // Find all temporary files created by this extension
      const tempFiles = nativeAddon.findTempFiles();
      
      if (tempFiles.length === 0) {
        vscode.window.showInformationMessage('No vulnerable temp files found. Try processing data first!');
        return;
      }

      // Create or get output channel
      const outputChannel = vscode.window.createOutputChannel("Temp Files Vulnerability Demo");
      outputChannel.clear();
      outputChannel.show(true);  // true = preserves focus
      
      outputChannel.appendLine(`VULNERABILITY DEMONSTRATION\n`);
      outputChannel.appendLine(`Found ${tempFiles.length} insecure temporary files:\n`);
      
      // For each temp file, read its content and append to our output channel
      for (let i = 0; i < tempFiles.length; i++) {
        const filePath = tempFiles[i];
        const content = nativeAddon.readTempFile(filePath);
        
        // Check if this is valid JSON and parse it
        try {
          const data = JSON.parse(content);
          outputChannel.appendLine(`File: ${filePath}`);
          outputChannel.appendLine(`- Created: ${data.timestamp}`);
          outputChannel.appendLine(`- Workspace: ${data.workspaceInfo.name}`);
          outputChannel.appendLine(`- Content: ${data.content}`);
          outputChannel.appendLine(`\nFULL DATA EXTRACTED:`);
          outputChannel.appendLine(`\`\`\`json`);
          outputChannel.appendLine(content);
          outputChannel.appendLine(`\`\`\`\n`);
        } catch (e) {
          // Not valid JSON, just show the raw content
          outputChannel.appendLine(`File: ${filePath}`);
          outputChannel.appendLine(`Raw content:`);
          outputChannel.appendLine(`\`\`\``);
          outputChannel.appendLine(content);
          outputChannel.appendLine(`\`\`\`\n`);
        }
      }
    } catch (error) {
      vscode.window.showErrorMessage(`Error demonstrating vulnerability: ${error.message}`);
    }
  });

  // Register a command to clean up all temporary files
  let cleanupCommand = vscode.commands.registerCommand('temp-files.cleanupTempFiles', function () {
    try {
      const removedFiles = nativeAddon.cleanup();
      if (removedFiles.length > 0) {
        vscode.window.showInformationMessage(`Cleaned up ${removedFiles.length} temporary files.`);
      } else {
        vscode.window.showInformationMessage('No temporary files to clean up.');
      }
    } catch (error) {
      vscode.window.showErrorMessage(`Error cleaning up: ${error.message}`);
    }
  });

  context.subscriptions.push(processCommand);
  context.subscriptions.push(exploitCommand);
  context.subscriptions.push(cleanupCommand);
}

function deactivate() {
  // Clean up any leftover temporary files when the extension is deactivated
  try {
    nativeAddon.cleanup();
  } catch (error) {
    console.error('Error cleaning up temporary files:', error);
  }
}

module.exports = {
  activate,
  deactivate
};