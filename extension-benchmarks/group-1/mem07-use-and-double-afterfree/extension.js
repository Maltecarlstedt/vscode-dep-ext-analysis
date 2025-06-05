const vscode = require('vscode');
const nativeAddon = require('./native/build/Release/addon.node');

function activate(context) {

    // Register Use-After-Free demo command
    let uafDemoCommand = vscode.commands.registerCommand('after-free-misuse.useAfterFree', async () => {
        try {
            // Create an output channel
            const outputChannel = vscode.window.createOutputChannel('Memory Vulnerabilities Demo');
            outputChannel.show();
            
            outputChannel.appendLine('Starting Use-After-Free vulnerability demonstration...');
            
            // Allocate a buffer
            const bufferSize = 100;
            outputChannel.appendLine(`Allocating buffer of size ${bufferSize}...`);
            nativeAddon.allocateBuffer(bufferSize);
            
            // Use the buffer (should be safe at this point)
            const bufferContent = nativeAddon.useBuffer();
            outputChannel.appendLine(`Buffer content: ${bufferContent}`);
            
            // Free the buffer
            outputChannel.appendLine('Freeing buffer...');
            nativeAddon.freeBuffer();
            
            // Ask user if they want to trigger the UAF vulnerability
            const result = await vscode.window.showWarningMessage(
                'Do you want to demonstrate the Use-After-Free vulnerability?',
                'Yes', 'No'
            );
            
            if (result === 'Yes') {
                // Use the buffer after it's been freed (UAF vulnerability)
                outputChannel.appendLine('Using buffer after it has been freed (UAF vulnerability)...');
                const uafResult = nativeAddon.useBuffer();
                outputChannel.appendLine(`UAF result (potentially corrupted data): ${uafResult}`);
                outputChannel.appendLine('This demonstrates a Use-After-Free vulnerability. In a real application, this could lead to crashes or security issues.');
            } else {
                outputChannel.appendLine('UAF demonstration cancelled.');
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Error in UAF demo: ${error.message}`);
        }
    });

    // Register Double-Free demo command
    let doubleFreeCommand = vscode.commands.registerCommand('after-free-misuse.doubleFree', async () => {
        try {
            // Create an output channel
            const outputChannel = vscode.window.createOutputChannel('Memory Vulnerabilities Demo');
            outputChannel.show();
            
            outputChannel.appendLine('Starting Double-Free vulnerability demonstration...');
            
            // Allocate a resource
            const resourceId = 1;
            outputChannel.appendLine(`Allocating resource with ID ${resourceId}...`);
            nativeAddon.allocateResource(resourceId);
            
            // Free the resource (first time)
            outputChannel.appendLine('Freeing resource (first time)...');
            const freeResult = nativeAddon.freeResource(resourceId);
            outputChannel.appendLine(`Free result: ${freeResult}`);
            
            // Ask user if they want to trigger the Double-Free vulnerability
            const result = await vscode.window.showWarningMessage(
                'Do you want to demonstrate the Double-Free vulnerability?',
                'Yes', 'No'
            );
            
            if (result === 'Yes') {
                // Free the resource again (Double-Free vulnerability)
                outputChannel.appendLine('Freeing resource again (Double-Free vulnerability)...');
                const doubleFreeResult = nativeAddon.forceDoubleFree(resourceId);
                outputChannel.appendLine(`Double-Free result: ${doubleFreeResult}`);
                outputChannel.appendLine('This demonstrates a Double-Free vulnerability. In a real application, this could lead to memory corruption, crashes, or security issues.');
            } else {
                outputChannel.appendLine('Double-Free demonstration cancelled.');
            }
        } catch (error) {
            vscode.window.showErrorMessage(`Error in Double-Free demo: ${error.message}`);
        }
    });

    context.subscriptions.push(uafDemoCommand);
    context.subscriptions.push(doubleFreeCommand);
}

function deactivate() {
}

module.exports = {
    activate,
    deactivate
};