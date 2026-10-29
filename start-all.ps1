﻿<#
.SYNOPSIS
    零知识密封加权评审系统（ZK-SealedWeigh）本地一键启动脚本。

.DESCRIPTION
    依次执行：启动本地 Hardhat 链 → 编译并部署合约 → 把新合约地址写入 backend\.env
    → 启动后端(Flask) → 启动前端(静态服务器)。

    前置条件：
      * Node.js 18 / 20 LTS（Hardhat 不支持 22+/25）
      * 已按 backend\requirements.txt 安装 Python 依赖（推荐 Python 3.9）
      * SQL Server 就绪，backend\.env 已填写（可由 backend\.env.example 复制）

.PARAMETER SkipDeploy
    跳过编译与部署，复用 backend\.env 中已有的 CONTRACT_ADDRESS。

.PARAMETER PythonExe
    后端/前端使用的 python 解释器路径。默认自动探测 %USERPROFILE%\.venvs\zkvoting。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\start-all.ps1
    powershell -ExecutionPolicy Bypass -File .\start-all.ps1 -SkipDeploy
#>
param(
    [switch]$SkipDeploy,
    [string]$PythonExe = ""
)

$ErrorActionPreference = "Stop"

$Root     = $PSScriptRoot
$Hardhat  = Join-Path $Root "hardhat-project"
$Backend  = Join-Path $Root "backend"
$Frontend = Join-Path $Root "frontend"
$EnvFile  = Join-Path $Backend ".env"

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Test-Port($port) {
    [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
}
function Wait-Port($port, $timeoutSec) {
    for ($i = 0; $i -lt $timeoutSec; $i++) {
        Start-Sleep -Seconds 1
        if (Test-Port $port) { return $true }
    }
    return $false
}

# ---------- 解析 Python 解释器 ----------
if (-not $PythonExe) {
    $candidate = Join-Path $env:USERPROFILE ".venvs\zkvoting\Scripts\python.exe"
    if (Test-Path $candidate) { $PythonExe = $candidate }
}
if ($PythonExe) {
    Write-Host "[i] 使用解释器: $PythonExe" -ForegroundColor Green
    $PythonCmd = "& '$PythonExe'"
} else {
    Write-Host "[!] 未找到虚拟环境，回退到 'py -3.9'，请确认依赖已安装。" -ForegroundColor Yellow
    $PythonCmd = "py -3.9"
}

# ---------- 前置校验 ----------
if (-not (Test-Path $EnvFile)) {
    Write-Host "[x] 未找到 $EnvFile" -ForegroundColor Red
    Write-Host "    请先复制 backend\.env.example 为 backend\.env 并填写。" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path (Join-Path $Hardhat "node_modules"))) {
    Write-Host "[!] hardhat-project 未安装依赖，请先在该目录执行 npm install。" -ForegroundColor Yellow
}

# ---------- 1) 本地链 ----------
Write-Step "1/5 检查本地链 (8545)"
if (Test-Port 8545) {
    Write-Host "[i] 8545 已在监听，复用现有链。" -ForegroundColor Green
} else {
    Write-Host "[i] 在新窗口启动 npx hardhat node ..." -ForegroundColor Green
    Start-Process -FilePath "powershell" `
        -ArgumentList "-NoExit", "-Command", "cd '$Hardhat'; npx hardhat node" | Out-Null
    if (-not (Wait-Port 8545 60)) {
        Write-Host "[x] 链未在 60s 内就绪，请查看链窗口的报错（Node 版本？）" -ForegroundColor Red
        exit 1
    }
    Write-Host "[i] 链已就绪。" -ForegroundColor Green
}

# ---------- 2) 编译 + 部署 ----------
if ($SkipDeploy) {
    Write-Step "2/5 跳过部署（-SkipDeploy）"
} else {
    Write-Step "2/5 编译并部署合约"
    Push-Location $Hardhat
    try {
        npx hardhat compile
        # 边实时打印边累积，避免部署期间看不到任何进度
        $deployOut = ""
        npx hardhat run scripts/deploy.ts --network localhost 2>&1 |
            ForEach-Object { Write-Host $_; $deployOut += "$_`n" }
    } finally {
        Pop-Location
    }

    $m = [regex]::Match($deployOut, 'CONTRACT_ADDRESS=(0x[0-9a-fA-F]{40})')
    if (-not $m.Success) {
        Write-Host "[x] 未能从部署输出解析出合约地址，请手动更新 .env 的 CONTRACT_ADDRESS。" -ForegroundColor Red
        exit 1
    }
    $addr = $m.Groups[1].Value

    $content = (Get-Content $EnvFile -Raw) -replace '(?m)^CONTRACT_ADDRESS=.*$', "CONTRACT_ADDRESS=$addr"
    [System.IO.File]::WriteAllText($EnvFile, $content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "[i] 已更新 .env: CONTRACT_ADDRESS=$addr" -ForegroundColor Green
}

# ---------- 3) 后端 ----------
Write-Step "3/5 启动后端 (5000)"
if (Test-Port 5000) {
    Write-Host "[i] 5000 已在监听，跳过启动。" -ForegroundColor Yellow
} else {
    Start-Process -FilePath "powershell" `
        -ArgumentList "-NoExit", "-Command", "`$env:PYTHONUTF8='1'; cd '$Backend'; $PythonCmd app.py" | Out-Null
    Write-Host "[i] 后端已在新窗口启动。" -ForegroundColor Green
}

# ---------- 4) 前端 ----------
Write-Step "4/5 启动前端 (3001)"
if (Test-Port 3001) {
    Write-Host "[i] 3001 已在监听，跳过启动。" -ForegroundColor Yellow
} else {
    Start-Process -FilePath "powershell" `
        -ArgumentList "-NoExit", "-Command", "cd '$Frontend'; $PythonCmd server.py" | Out-Null
    Write-Host "[i] 前端已在新窗口启动。" -ForegroundColor Green
}

# ---------- 5) 汇总 ----------
Write-Step "5/5 启动完成"
Write-Host "  前端 : http://127.0.0.1:3001" -ForegroundColor White
Write-Host "  后端 : http://127.0.0.1:5000/api/health" -ForegroundColor White
Write-Host "  链   : http://127.0.0.1:8545  (chainId 31337)" -ForegroundColor White
Write-Host ""
Write-Host "提示：若重启了链，链上投票计数会归零 —— 请重建数据库(database\init.sql)" -ForegroundColor Yellow
Write-Host "      或重新创建评审活动，否则旧记录的 blockchain_id 会指向已消失的编号。" -ForegroundColor Yellow
