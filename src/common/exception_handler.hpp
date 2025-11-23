#pragma once

#include <windows.h>
#include <winuser.h>

#include <sstream>

class exception_handler {
	static LONG WINAPI TopLevelExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo) {
		std::ostringstream stream;

		stream << "Unhandled exception\n";
		stream << "Exception code: 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << "\n";
		stream << "Address: " << ExceptionInfo->ExceptionRecord->ExceptionAddress << "\n";

		printf("%s\n", stream.str().c_str());
		MessageBoxA(nullptr, stream.str().c_str(), "Crashed!", MB_OK | MB_ICONERROR);

		return EXCEPTION_EXECUTE_HANDLER;
	}

public:
	static void init() {
		SetUnhandledExceptionFilter(&TopLevelExceptionFilter);
	}
};
