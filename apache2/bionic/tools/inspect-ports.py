#!/usr/bin/env python3
"""Collect exact Jammy candidate diffs and Bionic source neighborhoods for human review."""
import pathlib, subprocess, sys, re, difflib, shutil
if len(sys.argv)!=4: sys.exit("usage: inspect-ports.py BIONIC_TREE JAMMY_TREE REPORT_DIR")
bionic,jammy,out=[pathlib.Path(x).resolve() for x in sys.argv[1:]]
out.mkdir(parents=True,exist_ok=True)
names=["CVE-2026-56154.patch","CVE-2026-63686.patch",
       "CVE-2026-59797.patch","CVE-2026-46729.patch","CVE-2026-47360.patch",
       "CVE-2026-44119.patch"]
sections=["# Bionic patch context inspection (source-only)","",
          "Raw vendor patches are retained under `patches/` for review.",
          "All commands use dry-run with fuzz=0; no binary has been built.",""]
for name in names:
    source=jammy/"debian/patches"/name
    if not source.is_file(): raise RuntimeError("Missing patch "+str(source))
    shutil.copy2(source,out/"patches"/name) if (out/"patches").mkdir(exist_ok=True) is None else None
    data=source.read_text(encoding="utf-8",errors="replace")
    p=subprocess.run(["patch","--dry-run","--batch","--fuzz=0","-p1","-i",str(source)],
       cwd=bionic,universal_newlines=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=45)
    sections += ["## "+name,"","### Dry-run output","","```text",p.stdout.rstrip(),"```",""]
    filenames=re.findall(r"(?m)^\+\+\+ (?:b/)?([^\t\n ]+)",data)
    for rel in sorted(set(filenames)):
        f=bionic/rel
        if not f.is_file(): sections+=["Missing Bionic file: "+rel,""];continue
        lines=f.read_text(encoding="utf-8",errors="replace").splitlines()
        sections+=["### Source file: `"+rel+"`",""]
        # Each patch hunk provides an anchor; find the closest Bionic
        # neighborhood using context/removal lines, rather than old Jammy line numbers.
        patch_lines=data.splitlines()
        anchors=[]
        for i,line in enumerate(patch_lines):
            if not line.startswith("@@ "):continue
            j=i+1
            block=[]
            while j<len(patch_lines) and not patch_lines[j].startswith(("@@ ","diff ","--- ","+++ ")):
                l=patch_lines[j]
                if l.startswith((" ","-")): block.append(l[1:])
                j+=1
            if not block:continue
            # Find the longest distinctive, non-empty context/old line.
            filtered=[t.strip() for t in block if len(t.strip())>=14 and not t.strip().startswith(("*","//"))]
            if not filtered:continue
            best=None
            for q in filtered:
                exact=[k for k,row in enumerate(lines) if q in row]
                if len(exact)==1:
                    best=exact[0];break
            if best is None: continue
            if best in anchors:continue
            anchors.append(best)
            lo=max(0,best-10);hi=min(len(lines),best+20)
            sections+=["Bionic lines "+str(lo+1)+"-"+str(hi)+" around anchor:", "",
                       "```c",*(str(k+1)+": "+lines[k] for k in range(lo,hi)),"```",""]
        if not anchors: sections+=["No unambiguous hunk context anchor found; inspect the raw patch.",""]
(out/"port-context.md").write_text("\n".join(sections)+"\n",encoding="utf-8")
print("Inspection written to",out,"files",len(names))

# Focused view of BOTH rewrite subrequest lookahead branches in Bionic.
rewrite=(bionic/"modules/mappers/mod_rewrite.c").read_text(encoding="utf-8",errors="replace").splitlines()
positions=[i for i,line in enumerate(rewrite) if "ap_destroy_sub_req(rr);" in line]
focus=["# Bionic rewrite lookahead subrequest lifetime review","",
       "Positions containing ap_destroy_sub_req(rr): "+str([p+1 for p in positions]),""]
for idx in positions:
    lo=max(0,idx-24);hi=min(len(rewrite),idx+15)
    focus.extend(["## Bionic lines "+str(lo+1)+"-"+str(hi),"","```c"])
    focus.extend(str(k+1)+": "+rewrite[k] for k in range(lo,hi))
    focus.extend(["```",""])
(out/"rewrite-lookahead-source.md").write_text("\n".join(focus)+"\n",encoding="utf-8")

# Determine how Jammy defines the file-function restriction and whether
# Bionic expression API contains equivalent enforcement.
expr=[] 
for root in ["include","server","modules/ssl"]:
    for p in (bionic/root).rglob("*.[ch]"):
        lines=p.read_text(encoding="utf-8",errors="replace").splitlines()
        hits=[i for i,line in enumerate(lines) if
              "AP_EXPR_FLAG" in line or "ap_expr_lookup" in line or "file_func" in line]
        if not hits: continue
        # Include only files directly involved in flag definitions/lookup.
        if not ("ap_expr" in p.name or "util_expr" in p.name): continue
        expr.extend(["## "+str(p.relative_to(bionic)),""])
        for ix in hits[:45]:
            lo=max(0,ix-2);hi=min(len(lines),ix+3)
            expr.extend(str(k+1)+": "+lines[k] for k in range(lo,hi))
            expr.append("")
(out/"bionic-expression-api.txt").write_text("\n".join(expr)+"\n",encoding="utf-8")
