
const vscode = require('vscode');
const nativeAddon = require('./native/build/Release/addon.node');

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('Buffer Overflow Demo extension is now active');

    // Command to demonstrate unsafe memcpy
    const unsafeMemcpyCmd = vscode.commands.registerCommand(
        'buffer-overflows.unsafeMemcpy', 
        async () => {
            try {
                // Create a buffer larger than the fixed-size buffer in the native module
                const largeBuffer = Buffer.alloc(1024, 'A');
                
                // Pass to unsafe native function
                const result = nativeAddon.unsafeMemcpy(largeBuffer);
                
                vscode.window.showInformationMessage(`Operation completed: ${result}`);
            } catch (error) {
                vscode.window.showErrorMessage(`Error: ${error.message}`);
            }
        }
    );

    // Command to demonstrate unsafe strcpy
    const unsafeStrcpyCmd = vscode.commands.registerCommand(
        'buffer-overflows.unsafeStrcpy', 
        async () => {
            try {
                // Get text from active editor
                const editor = vscode.window.activeTextEditor;
                if (!editor) {
                    vscode.window.showInformationMessage('No text editor is active');
                    return;
                }
                
                const text = editor.document.getText(editor.selection);
                
                // Pass to unsafe native function
                const result = nativeAddon.unsafeStrcpy(text);
                
                vscode.window.showInformationMessage(`Operation completed: ${result}`);
            } catch (error) {
                vscode.window.showErrorMessage(`Error: ${error.message}`);
            }
        }
    );

    // Command to demonstrate unsafe strcat
    const unsafeStrcatCmd = vscode.commands.registerCommand(
        'buffer-overflows.unsafeStrcat', 
        async () => {
            try {
                const userInput = await vscode.window.showInputBox({
                    placeHolder: 'Enter text to append',
                    prompt: 'This will be appended to "Hello, " using unsafe strcat'
                });
                
                if (userInput) {
                    // Pass to unsafe native function
                    const result = nativeAddon.unsafeStrcat(userInput);
                    
                    vscode.window.showInformationMessage(`Operation completed: ${result}`);
                }
            } catch (error) {
                vscode.window.showErrorMessage(`Error: ${error.message}`);
            }
        }
    );

    // Command to demonstrate malloc too small
    const mallocTooSmallCmd = vscode.commands.registerCommand(
        'buffer-overflows.mallocTooSmall', 
        async () => {
            try {
                const userInput = await vscode.window.showInputBox({
                    placeHolder: 'Enter a string',
                    prompt: 'This will be processed with malloc without space for null terminator'
                });
                
                if (userInput) {
                    // Pass to unsafe native function
                    const result = nativeAddon.mallocTooSmall(userInput);
                    
                    vscode.window.showInformationMessage('Operation completed');
                }
            } catch (error) {
                vscode.window.showErrorMessage(`Error: ${error.message}`);
            }
        }
    );

    // Safe operations commands
    const safeMemcpyCmd = vscode.commands.registerCommand(
        'buffer-overflows.safeMemcpy', 
        async () => {
            try {
                // Create a large buffer
                const largeBuffer = Buffer.alloc(1024, 'A');
                
                // Pass to safe native function
                nativeAddon.safeMemcpy(largeBuffer);
                
                vscode.window.showInformationMessage('Safe operation completed successfully');
            } catch (error) {
                vscode.window.showErrorMessage(`Error: ${error.message}`);
            }
        }
    );

    context.subscriptions.push(
        unsafeMemcpyCmd,
        unsafeStrcpyCmd,
        unsafeStrcatCmd,
        mallocTooSmallCmd,
        safeMemcpyCmd
    );
}

function deactivate() {
    // Clean up resources
}

module.exports = {
    activate,
    deactivate
};