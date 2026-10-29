#requires -version 5.1
<#
.SYNOPSIS
    P2.8 一键验收：把项目所有可自动化验证的结论一次跑完。

.DESCRIPTION
    依次执行：
      1. hardhat 契约测试（digest + rangeProof，不含 fuzz）
      2. circuits 链下证明脚本（9 项）
      3. backend/tests/test_protocol.py（协议向量与 Pedersen 原语）
      4. backend/tests/test_api.py（API 契约与后门回归）
      5. backend/tests/e2e_flow.py（新建活动 -> 承诺 -> 范围证明 -> 揭晓 -> 结算 -> 审计包）
      6. frontend/tests/recovery.test.js（P3.1 恢复密码学核心：Shamir/AES-GCM/ECDH）
      7. backend/tests/recovery_flow.py（P3.2/P3.3 门限恢复：公钥、托管、请求、份额投递、本地重构）
      8. backend/tests/recovery_stress.py（P3.6 多评委压力测试：3 评委 k=2，单份不可恢复）
      9. frontend/tests/recovery-key-store.test.js（P3.4 钱包派生私钥持久化）
     10. backend/tests/model_check.py（P4 有界模型检验：阶段单调性等 7 条不变量）
     11. hardhat-project/test/fuzz.test.ts（P4 合约状态机模糊测试）
     12. backend/tests/test_fuzz_api.py + frontend/tests/recovery-fuzz.test.js（P4 接口/密码学模糊测试）

    前置条件：hardhat 链（8545）与 Flask 后端（5000）已在运行，合约已部署。
    脚本不会启动或重启任何服务，只做验证。

.PARAMETER Python
    指定 Python 解释器。默认使用项目 venv（如不存在则退回 PATH 中的 python）。

.PARAMETER FailFast
    任一环节失败立即停止；默认跑完全部环节再汇总。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\verify-all.ps1
    powershell -ExecutionPolicy Bypass -File .\verify-all.ps1 -FailFast
#>
param(
    [string]$Python = "C:\Users\34245\.venvs\zkvoting\Scripts\python.exe",
    [switch]$FailFast
)

$ErrorActionPreference = 'Continue'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$results = New-Object System.Collections.ArrayList
$script:failedSteps = 0

function Write-Section([string]$Text) {
    Write-Host ""
    Write-Host ("=" * 68) -ForegroundColor DarkCyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ("=" * 68) -ForegroundColor DarkCyan
}

function Invoke-Step {
    param(
        [string]$Name,
        [string]$WorkDir,
        [scriptblock]$Action
    )

    Write-Host ""
    Write-Host ("--- " + $Name + " ---") -ForegroundColor Yellow

    Push-Location $WorkDir
    try {
        & $Action
    } finally {
        Pop-Location
    }

    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }

    $passed = ($code -eq 0)
    $label = if ($passed) { "PASS" } else { "FAIL(exit=$code)" }
    $color = if ($passed) { "Green" } else { "Red" }
    Write-Host ("[结果] " + $Name + " -> " + $label) -ForegroundColor $color

    [void]$results.Add([pscustomobject]@{
        Step = $Name
        Code = $code
        Pass = $passed
    })

    if (-not $passed) {
        $script:failedSteps = $script:failedSteps + 1
        if ($FailFast) {
            throw ("失败即停止：" + $Name)
        }
    }
}

# ==================== 0. 前置检查 ====================
Write-Section "0. 前置检查"

if (-not (Test-Path $Python)) {
    Write-Host ("[提示] 未找到 venv Python：" + $Python + "，改用 PATH 中的 python") -ForegroundColor Yellow
    $Python = "python"
}
Write-Host ("Python : " + $Python)

$requiredPorts = @(
    @{ Port = 8545; Name = "Hardhat 链" },
    @{ Port = 5000; Name = "Flask 后端" }
)
$precheckOk = $true
foreach ($item in $requiredPorts) {
    $listening = Get-NetTCPConnection -LocalPort $item.Port -State Listen -ErrorAction SilentlyContinue
    if ($listening) {
        Write-Host ("[OK]   " + $item.Name + " 端口 " + $item.Port + " 在线") -ForegroundColor Green
    } else {
        Write-Host ("[FAIL] " + $item.Name + " 端口 " + $item.Port + " 未监听") -ForegroundColor Red
        $precheckOk = $false
    }
}

$requiredFiles = @(
    "circuits\build\proof_fixture.json",
    "circuits\range_proof.zkey",
    "circuits\build\range_proof_js\range_proof.wasm",
    "frontend\vendor\zk\snarkjs.min.js",
    "frontend\vendor\zk\range_proof.wasm",
    "frontend\vendor\zk\range_proof.zkey"
)
foreach ($relative in $requiredFiles) {
    $full = Join-Path $scriptDir $relative
    if ((Test-Path $full) -and ((Get-Item $full).Length -gt 0)) {
        Write-Host ("[OK]   构件存在 " + $relative) -ForegroundColor Green
    } else {
        Write-Host ("[FAIL] 缺少构件 " + $relative) -ForegroundColor Red
        $precheckOk = $false
    }
}

if (-not $precheckOk) {
    Write-Host ""
    Write-Host "前置条件不满足：请先运行 .\start-all.ps1，并确保合约已部署。" -ForegroundColor Red
    exit 1
}

$env:PYTHONUTF8 = "1"

# ==================== 1-12. 验收环节 ====================
Write-Section "一键验收"

try {
    Invoke-Step -Name "1/12 合约测试（digest + rangeProof）" -WorkDir (Join-Path $scriptDir "hardhat-project") -Action {
        & npx hardhat test test\digest.test.ts test\rangeProof.test.ts
    }

    Invoke-Step -Name "2/12 链下范围证明（prove.js）" -WorkDir (Join-Path $scriptDir "circuits") -Action {
        & node scripts\prove.js
    }

    Invoke-Step -Name "3/12 协议单元测试（test_protocol.py）" -WorkDir (Join-Path $scriptDir "backend") -Action {
        & $Python tests\test_protocol.py
    }

    Invoke-Step -Name "4/12 API 契约测试（test_api.py）" -WorkDir (Join-Path $scriptDir "backend") -Action {
        & $Python tests\test_api.py
    }

    Invoke-Step -Name "5/12 端到端验收（e2e_flow.py）" -WorkDir (Join-Path $scriptDir "backend") -Action {
        & $Python tests\e2e_flow.py
    }

    Invoke-Step -Name "6/12 恢复密码学核心（recovery.test.js）" -WorkDir $scriptDir -Action {
        & node frontend\tests\recovery.test.js
    }

    Invoke-Step -Name "7/12 门限恢复流程（recovery_flow.py）" -WorkDir (Join-Path $scriptDir "backend") -Action {
        & $Python tests\recovery_flow.py
    }

    Invoke-Step -Name "8/12 多评委压力测试（recovery_stress.py）" -WorkDir (Join-Path $scriptDir "backend") -Action {
        & $Python tests\recovery_stress.py
    }

    Invoke-Step -Name "9/12 私钥持久化（recovery-key-store.test.js）" -WorkDir $scriptDir -Action {
        & node frontend\tests\recovery-key-store.test.js
    }

    Invoke-Step -Name "10/12 有界模型检验（model_check.py）" -WorkDir (Join-Path $scriptDir "backend") -Action {
        & $Python tests\model_check.py
    }

    Invoke-Step -Name "11/12 合约状态机模糊测试（fuzz.test.ts）" -WorkDir (Join-Path $scriptDir "hardhat-project") -Action {
        & npx hardhat test test\fuzz.test.ts
    }

    Invoke-Step -Name "12/12 接口与密码学模糊测试" -WorkDir (Join-Path $scriptDir "backend") -Action {
        & $Python tests\test_fuzz_api.py
        if ($LASTEXITCODE -ne 0) { return }
        & node ..\frontend\tests\recovery-fuzz.test.js
    }
}
catch {
    Write-Host ""
    Write-Host ("已按 -FailFast 停止：" + $_.Exception.Message) -ForegroundColor Yellow
}

# ==================== 汇总 ====================
Write-Section "汇总"

foreach ($item in $results) {
    $color = if ($item.Pass) { "Green" } else { "Red" }
    $label = if ($item.Pass) { "PASS" } else { "FAIL" }
    Write-Host ("  {0,-42} {1}" -f $item.Step, $label) -ForegroundColor $color
}

$total = $results.Count
$passedCount = $total - $script:failedSteps
Write-Host ""
if ($script:failedSteps -eq 0 -and $total -gt 0) {
    Write-Host ("全部通过：" + $passedCount + "/" + $total) -ForegroundColor Green
    exit 0
} else {
    Write-Host ("存在失败：" + $script:failedSteps + " / " + $total) -ForegroundColor Red
    exit 1
}
