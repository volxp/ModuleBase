#pragma once
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <Psapi.h>
#include "ntdlldefs.h"
#include "ThreadPool.h"
#include "WorkerFactory.h"

bool CreateTPDirectThread(HANDLE process, void* addr);