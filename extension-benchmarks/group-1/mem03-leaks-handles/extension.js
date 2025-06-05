const vscode = require('vscode');
const nativeAddon = require('./native/build/Release/addon.node');

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {

    let disposable = vscode.commands.registerCommand('leaks-handles.demonstrateMemoryLeak', async () => {
        const count = await vscode.window.showInputBox({
            prompt: 'How many objects to leak?',
            placeHolder: '100'
        });
        
        const size = await vscode.window.showInputBox({
            prompt: 'Size of each object (bytes)',
            placeHolder: '1024'
        });
        
        try {
            const leakedCount = nativeAddon.leakObjects(parseInt(count) || 100, parseInt(size) || 1024);
            const stats = nativeAddon.getStats();
            
            vscode.window.showInformationMessage(
                `Created ${leakedCount} leak objects. Total stored references: ${stats.storedReferences}`
            );
        } catch (err) {
            vscode.window.showErrorMessage(`Failed to create memory leak: ${err.message}`);
        }
    });
    
    // Command to store a function that will never be cleaned up
    let storeFunctionCmd = vscode.commands.registerCommand('leaks-handles.storeFunction', () => {
        try {
            // Creating a simple function that will never be cleaned up
            const functionIndex = nativeAddon.storeFunction(() => {
                console.log('This is a leaked function');
                return 'Function result';
            });
            
            vscode.window.showInformationMessage(`Stored function at index ${functionIndex}`);
        } catch (err) {
            vscode.window.showErrorMessage(`Failed to store function: ${err.message}`);
        }
    });
    
    // Command to call a stored function
    let callFunctionCmd = vscode.commands.registerCommand('leaks-handles.callStoredFunction', async () => {
        const index = await vscode.window.showInputBox({
            prompt: 'Enter function index to call',
            placeHolder: '0'
        });
        
        try {
            const result = nativeAddon.callFunction(parseInt(index) || 0);
            vscode.window.showInformationMessage(`Function result: ${result}`);
        } catch (err) {
            vscode.window.showErrorMessage(`Failed to call function: ${err.message}`);
        }
    });
    
    // Command to attempt cleanup (but with potential issues)
    let cleanupCmd = vscode.commands.registerCommand('leaks-handles.attemptCleanup', async () => {
        const count = await vscode.window.showInputBox({
            prompt: 'How many references to clean up?',
            placeHolder: 'all'
        });
        
        try {
            const stats = nativeAddon.getStats();
            const cleanupCount = count === 'all' ? stats.storedReferences : parseInt(count) || 0;
            const cleaned = nativeAddon.cleanup(cleanupCount);
            const newStats = nativeAddon.getStats();
            
            vscode.window.showInformationMessage(
                `Attempted to clean ${cleanupCount} references. Cleaned: ${cleaned}. ` +
                `Remaining: ${newStats.storedReferences}`
            );
        } catch (err) {
            vscode.window.showErrorMessage(`Cleanup failed: ${err.message}`);
        }
    });

    let getStats = vscode.commands.registerCommand('leaks-handles.getStats', () => {
        try {
            const stats = nativeAddon.getStats();
            vscode.window.showInformationMessage(
                `Stored references: ${stats.storedReferences}, ` +
                `Total leaked objects: ${stats.capacity}`
            );
        } catch (err) {
            vscode.window.showErrorMessage(`Failed to get stats: ${err.message}`);
        }
    });
    
    // Register all commands
    context.subscriptions.push(disposable);
    context.subscriptions.push(storeFunctionCmd);
    context.subscriptions.push(callFunctionCmd);
    context.subscriptions.push(cleanupCmd);
}

function deactivate() {
    // This function is called when your extension is deactivated
    // Note: We intentionally don't clean up the stored references to demonstrate memory leaks
    console.log('Memory leak demonstration extension deactivated');
}

module.exports = {
    activate,
    deactivate
};