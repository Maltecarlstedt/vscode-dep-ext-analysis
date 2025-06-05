const vscode = require('vscode');
const path = require('path');
const fs = require('fs');

const nativeAddon = require(path.join(__dirname, './native/build/Release/addon.node'));

/**
 * Activate the extension
 * @param {vscode.ExtensionContext} context 
 */
function activate(context) {
    // Register commands
    let executeCommandCmd = vscode.commands.registerCommand(
        'cmd-injection.executeCommand', 
        executeCommandHandler
    );

    let executeEchoCmd = vscode.commands.registerCommand(
        'cmd-injection.executeEcho', 
        executeEchoHandler
    );

    context.subscriptions.push(executeCommandCmd);
    context.subscriptions.push(executeEchoCmd);
}

/**
 * Handler for the executeCommand command
 */
async function executeCommandHandler() {
    try {
        // Prompt user for a command to execute
        const command = await vscode.window.showInputBox({
            prompt: 'Enter a shell command to execute',
            placeHolder: 'ls -la',
            ignoreFocusOut: true,
            validateInput: (text) => {
                return text ? null : 'Command cannot be empty';
            }
        });
        
        if (!command) {
            return; // User cancelled
        }
        
        // Show warning about command injection
        const proceed = await vscode.window.showWarningMessage(
            `CAUTION: You are about to execute: "${command}" via a vulnerable native module.`,
            { modal: true },
            'Proceed Anyway'
        );
        
        if (proceed !== 'Proceed Anyway') {
            return; // User cancelled
        }
        
        // Create output channel to display results
        const outputChannel = vscode.window.createOutputChannel('Command Execution Result');
        outputChannel.show();
        outputChannel.appendLine(`Executing command: ${command}`);
        outputChannel.appendLine('=========================================');
        
        // Execute the command through the native module
        try {
            const exitCode = nativeAddon.executeCommand(command);
            outputChannel.appendLine(`Command execution finished with exit code: ${exitCode}`);
        } catch (error) {
            outputChannel.appendLine(`Error executing command: ${error.message}`);
        }
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to load native module: ${error.message}`);
    }
}

/**
 * Handler for the executeEcho command
 */
async function executeEchoHandler() {
    try {
        // Prompt user for input to echo
        const userInput = await vscode.window.showInputBox({
            prompt: 'Enter text to echo (vulnerable to command injection)',
            placeHolder: 'Hello World',
            ignoreFocusOut: true
        });
        
        if (!userInput) {
            return; // User cancelled
        }
        
        // Create output channel to display results
        const outputChannel = vscode.window.createOutputChannel('Echo Command Result');
        outputChannel.show();
        outputChannel.appendLine(`Executing echo with input: ${userInput}`);
        outputChannel.appendLine('=========================================');
        
        // Execute the echo command through the native module
        try {
            const exitCode = nativeAddon.executeCommandWithEcho(userInput);
            outputChannel.appendLine(`Command execution finished with exit code: ${exitCode}`);
            
            // Add educational note about command injection
            outputChannel.appendLine('\n=========================================');
            outputChannel.appendLine('SECURITY NOTE:');
            outputChannel.appendLine('This demonstration uses vulnerable code that directly concatenates');
            outputChannel.appendLine('user input into a command string without proper sanitization.');
            outputChannel.appendLine('Try entering: Hello World; ls -la');
            outputChannel.appendLine('or: Hello World && whoami');
            outputChannel.appendLine('to see how command injection works.');
        } catch (error) {
            outputChannel.appendLine(`Error executing command: ${error.message}`);
        }
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to load native module: ${error.message}`);
    }
}

function deactivate() {}

module.exports = {
    activate,
    deactivate
};