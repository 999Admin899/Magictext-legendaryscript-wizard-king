#!/bin/bash
#brazilian script of group jhonadev
A='\033[34m';V='\033[31m';R='\033[0m'
TF=()
cl(){ for f in "${TF[@]}";do [ -f "$f" ]&&rm -f -- "$f";done;printf '%b' "$R"; }
trap 'cl;echo "Interrompido.";exit 130' INT TERM
trap cl EXIT
CF=0
tc(){ command -v termux-reload-settings>/dev/null 2>&1||{ echo "Não é Termux.";return; }
read -p "Mudar cor do Termux? [s/N] " r
[[ "$r" =~ ^[sS]$ ]]||return
mkdir -p "$HOME/.termux"
[ -f "$HOME/.termux/colors.properties" ]&&cp "$HOME/.termux/colors.properties" "$HOME/.termux/colors.properties.bak"
printf 'background=#ffffff\nforeground=#0000ff\n' > "$HOME/.termux/colors.properties"
termux-reload-settings;CF=1;echo "Backup salvo."; }
echo -e "${A}Checando deps...${R}"
command -v xxd r2 objdump readelf nm strings nano>/dev/null 2>&1||{
pkg install -y xxd binutils radare2 file coreutils python nano>/dev/null 2>&1||{
echo -e "${V}Falha nas deps.${R}";read -p "Continuar? [s/N] " c;[[ "$c" =~ ^[sS]$ ]]||exit 1;};}
read -p "Arquivo alvo: " F
[ -f "$F" ]||{ echo "Não encontrado.";exit 1; }
pg(){ command -v less>/dev/null 2>&1&&less -R||cat; }
vn(){ [[ "$1" =~ ^[0-9]+$ ]]; }
D="$(dirname -- "$F")";D="${D:-.}";B="$(basename -- "$F")";BD="$D/.backups_$B";mkdir -p "$BD"
bk(){ local t b;t=$(date +%Y%m%d_%H%M%S);b="$BD/${t}.bak";cp -- "$F" "$b"&&echo "Backup: $b" >&2;echo "$b"; }
cf(){ echo -e "${V}⚠  $1${R}";read -p "Digite SIM pra continuar: " c;[ "$c" = "SIM" ]; }
tp(){ file -b -- "$F" 2>/dev/null; }
ck(){ local a="$1" d;d="$(tp)";[ "$a" != "$d" ]&&{ echo -e "${V}⚠  Tipo mudou: '$a' -> '$d'. Use opção 22.${R}";}; }
PY='import os,tempfile,stat
def salvar(arq,data):
 d=os.path.dirname(os.path.abspath(arq)) or "."
 fd,tmp=tempfile.mkstemp(dir=d)
 try:
  with os.fdopen(fd,"wb") as f:f.write(data)
  os.chmod(tmp,stat.S_IMODE(os.stat(arq).st_mode))
  os.replace(tmp,arq)
 except Exception:
  try:os.unlink(tmp)
  except OSError:pass
  raise'
while true;do
echo -e "${A}"
echo "========= MENU v3 ========="
echo "Arquivo: $F  [$(tp)]"
echo "--- Análise ---"
echo " 1 primeiros 4 bytes + file"
echo " 2 strings ASCII"
echo " 3 C-pseudo (r2 pdg)"
echo " 4 asm (r2 pdf)"
echo " 5 view hex paginado"
echo " 6 xxd completo"
echo " 9 bytes 7F"
echo "10 U+FFFD"
echo "11 objdump -d"
echo "12 espaços 0x20"
echo "15 detectar tipo por magic"
echo "16 strings + hex + UTF-16"
echo "18 strings mais repetidas"
echo "32 últimos 4 bytes"
echo "40 readelf -h"
echo "41 readelf -S"
echo "42 nm -D"
echo "43 objdump -h"
echo "44 busca hex ou texto"
echo "45 filtro tempo real"
echo "46 xxd destacando ; : invisíveis"
echo "47 posições de ;"
echo "48 posições de :"
echo "49 posições de , e ."
echo "50 posições de !"
echo "51 posições de '"
echo "52 posições de \""
echo "53 strings UTF-8 multibyte"
echo "54 strings UTF-16 LE/BE"
echo "55 cat do arquivo"
echo "--- Edição ---"
echo " 7 deletar bytes em offset"
echo " 8 deletar U+FFFD"
echo "13 deletar '@'"
echo "14 deletar '^'"
echo "17 substituir string"
echo "19 remover strings +repetidas"
echo "20 remover strings -repetidas"
echo "25 inserir bytes"
echo "26 substituir hex"
echo "27 0x30->0x31"
echo "28 0x31->0x30"
echo "30 mudar 4 primeiros bytes"
echo "31 mudar byte(s) em offset"
echo "35 zerar 4 primeiros"
echo "36 zerar 8 primeiros"
echo "56 editor hex (xxd->nano->xxd -r)"
echo "57 remover ';'"
echo "58 remover ':'"
echo "59 editor nano"
echo "--- Arquivo ---"
echo "21 antes/depois"
echo "22 restaurar backup"
echo "23 salvar cópia"
echo "24 radare2 interativo"
echo "29 renomear"
echo "33 salvar 1ª metade"
echo "34 salvar 2ª metade"
echo "38 cores do Termux"
echo " 0 sair"
echo "========================"
echo -e "${R}"
read -p "Escolha: " OP
TA="$(tp)"
case "$OP" in
1) xxd -l 4 -- "$F" 2>&1;file -- "$F" 2>&1;read -p "Enter..." ;;
2) strings -n 4 -- "$F" 2>&1|pg ;;
3) r2 -e bin.relocs.apply=true -Aqc "aaa;af;s main;af;afv;pdg" -- "$F" 2>&1|pg ;;
4) r2 -e bin.relocs.apply=true -Aqc "aaa;s main;pdf" -- "$F" 2>&1|pg ;;
5|6) xxd -- "$F" 2>&1|pg ;;
7) read -p "Offset hex: " O;read -p "Qtd bytes: " Q
[[ "$O" =~ ^[0-9a-fA-F]+$ ]]&&vn "$Q"||{ echo "Inválido.";read -p "Enter...";continue; }
bk>/dev/null
F="$F" O="$O" Q="$Q" python3 - <<PY
import os
$PY
f=os.environ['F'];o=int(os.environ['O'],16);q=int(os.environ['Q'])
d=open(f,'rb').read()
if o+q>len(d):print(f"Aviso: qtd={len(d)-o}");q=max(0,len(d)-o)
salvar(f,d[:o]+d[o+q:])
print(f"{q} bytes removidos em 0x{o:x}")
PY
ck "$TA";read -p "Enter..." ;;
8) bk>/dev/null
F="$F" python3 - <<PY
import os
$PY
f=os.environ['F'];d=open(f,'rb').read();n=d.count(b'\xef\xbf\xbd')
salvar(f,d.replace(b'\xef\xbf\xbd',b''))
print(f"{n} U+FFFD removidos")
PY
ck "$TA";read -p "Enter..." ;;
9) F="$F" python3 - <<'PY' 2>&1|pg
import os
d=open(os.environ['F'],'rb').read();t=0
for i,b in enumerate(d):
 if b==0x7f:print(f"{i:08x}: 7f");t+=1
print(f"--- total {t} ---")
PY
;;
10) F="$F" python3 - <<'PY' 2>&1|pg
import os
d=open(os.environ['F'],'rb').read();i=0;t=0
while True:
 i=d.find(b'\xef\xbf\xbd',i)
 if i<0:break
 print(f"{i:08x}: U+FFFD");i+=3;t+=1
print(f"--- total {t} ---")
PY
;;
11) objdump -d -- "$F" 2>&1|pg ;;
12) F="$F" python3 - <<'PY' 2>&1|pg
import os
d=open(os.environ['F'],'rb').read();t=0
for i,b in enumerate(d):
 if b==0x20:print(f"{i:08x}: 20");t+=1
print(f"--- total {t} ---")
PY
;;
13|14) C='@';[ "$OP" = "14" ]&&C='^'
cf "Remover TODOS '$C'. Quebra ELF/DEX/ZIP."||continue
bk>/dev/null
F="$F" C="$C" python3 - <<PY
import os
$PY
f=os.environ['F'];c=os.environ['C'].encode();d=open(f,'rb').read();n=d.count(c)
salvar(f,d.replace(c,b''))
print(f"{n} removidos")
PY
ck "$TA";read -p "Enter..." ;;
15) F="$F" python3 - <<'PY' 2>&1
import os
f=os.environ['F']
with open(f,'rb') as fp:h=fp.read(8);fp.seek(0);a=fp.read(4096)
m=h[:4];print(f"4 bytes: {m.hex()}  ({m!r})")
def t(b):return bool(b) and all(9<=x<=13 or 32<=x<=126 for x in b[:128])
d="desconhecido"
if m==b'\x7fELF':d="ELF"
elif m[:4]==b'dex\n':d="dex"
elif m[:2]==b'PK':d="apk/zip"
elif m[:2]==b'\x1f\x8b':d="gzip"
elif m[:4]==b'\x89PNG':d="png"
elif m[:3]==b'\xff\xd8\xff':d="jpg"
elif h.startswith(b'#!'):d="sh"
elif t(a):d="txt"
print("Detecção:",d)
_,e=os.path.splitext(f);print(f"Ext: {e or '(nenhuma)'}")
PY
read -p "Enter..." ;;
16) F="$F" python3 - <<'PY' 2>&1|pg
import os,subprocess,re
f=os.environ['F'];L=100
print("=== ASCII >=6 ===")
d=open(f,'rb').read();n=0
for m in re.finditer(rb'[\x20-\x7e]{6,}',d):
 print(f"0x{m.start():08x}  {m.group().decode('ascii','replace')}");n+=1
 if n>=L:print(f"... {L}");break
for e,enc in [('l','UTF-16LE'),('b','UTF-16BE')]:
 print(f"\n=== {enc} ===")
 try:
  r=subprocess.run(['strings','-n','4','-e',e,'--',f],capture_output=True,timeout=30)
  for l in r.stdout.splitlines()[:L]:print("  "+l.decode('ascii','replace'))
 except Exception as ex:print("  falha:",ex)
PY
;;
17) read -p "Antiga: " DE;read -p "Nova: " PA
[ -z "$DE" ]&&{ echo "Vazio.";read -p "Enter...";continue; }
if [ ${#DE} -ne ${#PA} ];then cf "Tamanhos diferem (${#DE} vs ${#PA}). Desloca offsets."||continue;fi
bk>/dev/null
F="$F" DE="$DE" PA="$PA" python3 - <<PY
import os
$PY
f=os.environ['F'];d=open(f,'rb').read()
de=os.environ['DE'].encode();pa=os.environ['PA'].encode()
n=d.count(de);salvar(f,d.replace(de,pa))
print(f"{n} substituições")
PY
ck "$TA";read -p "Enter..." ;;
18) F="$F" python3 - <<'PY' 2>&1|pg
import os,re
from collections import Counter
d=open(os.environ['F'],'rb').read()
c=Counter(re.findall(rb'[A-Za-z_][A-Za-z0-9_]{3,}',d))
print(f"Distintos: {len(c)}")
for w,n in c.most_common(100):print(f"{n:6d}  {w.decode('ascii','replace')}")
PY
;;
19|20) if [ "$OP" = "19" ];then read -p ">= " L;CM=">=";else read -p "<= " L;CM="<=";fi
vn "$L"||{ echo "Inválido.";read -p "Enter...";continue; }
cf "Isto quase sempre quebra ELF/DEX/ZIP."||continue
bk>/dev/null
F="$F" L="$L" CM="$CM" python3 - <<PY
import os,re
from collections import Counter
$PY
f=os.environ['F'];l=int(os.environ['L']);m=os.environ['CM']
d=open(f,'rb').read()
c=Counter(re.findall(rb'[A-Za-z_][A-Za-z0-9_]{3,}',d))
a=[w for w,n in c.items() if (n>=l if m==">=" else n<=l)]
nv=d;t=0
for w in a:t+=nv.count(w);nv=nv.replace(w,b'')
salvar(f,nv)
print(f"{len(a)} strings, {t} ocorrências")
PY
ck "$TA";read -p "Enter..." ;;
21) mapfile -t K < <(ls -1 "$BD"/*.bak 2>/dev/null|sort)
[ ${#K[@]} -eq 0 ]&&{ echo "Sem backups.";read -p "Enter...";continue; }
U="${K[-1]}";echo "Mais recente: $U"
stat -c '  %s bytes  %n' -- "$U" "$F"
sha256sum -- "$U" "$F" 2>&1
cmp -s -- "$U" "$F"&&echo "IDÊNTICOS."||echo "DIFERENTES."
read -p "Enter..." ;;
22) mapfile -t K < <(ls -1t "$BD"/*.bak 2>/dev/null)
[ ${#K[@]} -eq 0 ]&&{ echo "Sem backups.";read -p "Enter...";continue; }
for i in "${!K[@]}";do printf " %2d) %s  (%s)\n" "$i" "$(basename "${K[$i]}")" "$(stat -c%s "${K[$i]}")";done
read -p "Restaurar qual? " N
[ -z "$N" ]&&continue
vn "$N"&&[ "$N" -lt "${#K[@]}" ]||{ echo "Inválido.";read -p "Enter...";continue; }
AL="${K[$N]}"
read -p "Sobrescrever? [s/N] " r
if [[ "$r" =~ ^[sS]$ ]];then
cp -- "$F" "$BD/pre_restore_$(date +%Y%m%d_%H%M%S).bak"
cp -- "$AL" "$F";echo "Restaurado."
fi
read -p "Enter..." ;;
23) read -p "Destino (Enter=$F.save): " d;d="${d:-$F.save}"
cp -- "$F" "$d"&&echo "Salvo: $d";read -p "Enter..." ;;
24) r2 -- "$F" 2>&1 ;;
25) read -p "Offset hex: " O;read -p "Bytes hex: " H
[[ "$O" =~ ^[0-9a-fA-F]+$ ]]||{ echo "Inválido.";read -p "Enter...";continue; }
H="$(echo "$H"|tr -d ' ')"
[[ "$H" =~ ^[0-9a-fA-F]+$ && $(( ${#H}%2 )) -eq 0 ]]||{ echo "Hex inválido.";read -p "Enter...";continue; }
cf "Inserir bytes desloca offsets."||continue
bk>/dev/null
F="$F" O="$O" H="$H" python3 - <<PY
import os
$PY
f=os.environ['F'];o=int(os.environ['O'],16);a=bytes.fromhex(os.environ['H'])
d=open(f,'rb').read()
if o>len(d):o=len(d)
salvar(f,d[:o]+a+d[o:])
print(f"{len(a)} bytes em 0x{o:x}")
PY
ck "$TA";read -p "Enter..." ;;
26) read -p "Hex antigo: " O;read -p "Hex novo (vazio=apagar): " N
O="$(echo "$O"|tr -d ' ')";N="$(echo "$N"|tr -d ' ')"
[[ "$O" =~ ^[0-9a-fA-F]+$ && $(( ${#O}%2 )) -eq 0 ]]||{ echo "Inválido.";read -p "Enter...";continue; }
[ -n "$N" ]&&{ [[ "$N" =~ ^[0-9a-fA-F]+$ && $(( ${#N}%2 )) -eq 0 ]]||{ echo "Hex novo inválido.";read -p "Enter...";continue; }; }
bk>/dev/null
F="$F" O="$O" N="$N" python3 - <<PY
import os
$PY
f=os.environ['F'];o=bytes.fromhex(os.environ['O']);n=bytes.fromhex(os.environ['N']) if os.environ['N'] else b''
d=open(f,'rb').read();c=d.count(o)
salvar(f,d.replace(o,n))
print(f"{c} substituições")
PY
ck "$TA";read -p "Enter..." ;;
27|28) D='0';P='1';[ "$OP" = "28" ]&&{ D='1';P='0';}
cf "Trocar TODOS '$D' por '$P'."||continue
bk>/dev/null
F="$F" D="$D" P="$P" python3 - <<PY
import os
$PY
f=os.environ['F'];d=open(f,'rb').read()
de=os.environ['D'].encode();pa=os.environ['P'].encode()
n=d.count(de);salvar(f,d.replace(de,pa))
print(f"{n} bytes")
PY
ck "$TA";read -p "Enter..." ;;
29) read -p "Novo nome: " N
[ -z "$N" ]&&{ echo "Vazio.";read -p "Enter...";continue; }
mv -- "$F" "$N";F="$N";B="$(basename -- "$F")";D="$(dirname -- "$F")";D="${D:-.}";BD="$D/.backups_$B";mkdir -p "$BD"
echo "Renomeado: $F";read -p "Enter..." ;;
30) read -p "Novos 4 bytes (8 hex): " H;H="$(echo "$H"|tr -d ' ')"
[[ "$H" =~ ^[0-9a-fA-F]{8}$ ]]||{ echo "Precisa 8 hex.";read -p "Enter...";continue; }
cf "Corrompe o header."||continue
bk>/dev/null
F="$F" H="$H" python3 - <<PY
import os
$PY
f=os.environ['F'];nb=bytes.fromhex(os.environ['H']);d=open(f,'rb').read()
if len(d)<4:d=d.ljust(4,b'\x00')
salvar(f,nb+d[4:])
print(f"Header: {nb.hex()}")
PY
ck "$TA";read -p "Enter..." ;;
31) read -p "Offset hex: " O;read -p "Byte(s) hex: " H
[[ "$O" =~ ^[0-9a-fA-F]+$ ]]||{ echo "Inválido.";read -p "Enter...";continue; }
H="$(echo "$H"|tr -d ' ')"
[[ "$H" =~ ^[0-9a-fA-F]+$ && $(( ${#H}%2 )) -eq 0 ]]||{ echo "Hex inválido.";read -p "Enter...";continue; }
S=$(stat -c%s -- "$F");OD=$((16#$O))
[ $((OD+${#H}/2)) -gt "$S" ]&&{ echo -e "${V}Offset ultrapassa ($S).${R}";read -p "Enter...";continue; }
bk>/dev/null
F="$F" O="$O" H="$H" python3 - <<PY
import os
$PY
f=os.environ['F'];o=int(os.environ['O'],16);nb=bytes.fromhex(os.environ['H'])
d=bytearray(open(f,'rb').read())
d[o:o+len(nb)]=nb
salvar(f,bytes(d))
print(f"{len(nb)} byte(s) em 0x{o:x}")
PY
ck "$TA";read -p "Enter..." ;;
32) xxd -s -4 -- "$F" 2>&1;read -p "Enter..." ;;
33|34) read -p "Sufixo (Enter=.part): " S;S="${S:-.part}"
Z=$(stat -c%s -- "$F");H=$((Z/2))
if [ "$OP" = "33" ];then head -c "$H" -- "$F" > "${F}${S}1";echo "-> ${F}${S}1"
else tail -c +$((H+1)) -- "$F" > "${F}${S}2";echo "-> ${F}${S}2";fi
[ $((Z%2)) -ne 0 ]&&echo "Aviso: tamanho ímpar."
read -p "Enter..." ;;
35) cf "Zerar 4 primeiros."||continue
bk>/dev/null
F="$F" python3 - <<PY
import os
$PY
f=os.environ['F'];d=open(f,'rb').read()
if len(d)<4:d=d.ljust(4,b'\x00')
salvar(f,b'\x00\x00\x00\x00'+d[4:])
print("4 zerados")
PY
ck "$TA";read -p "Enter..." ;;
36) cf "Zerar 8 primeiros."||continue
bk>/dev/null
F="$F" python3 - <<PY
import os
$PY
f=os.environ['F'];d=open(f,'rb').read()
if len(d)<8:d=d.ljust(8,b'\x00')
salvar(f,b'\x00'*8+d[8:])
print("8 zerados")
PY
ck "$TA";read -p "Enter..." ;;
38) tc;read -p "Enter..." ;;
40) readelf -h -- "$F" 2>&1|pg ;;
41) readelf -S -- "$F" 2>&1|pg ;;
42) nm -D -- "$F" 2>&1|pg ;;
43) objdump -h -- "$F" 2>&1|pg ;;
44) read -p "Hex (h:xx) ou texto: " Q
if [[ "$Q" == h:* ]];then
H="${Q#h:}";H="$(echo "$H"|tr -d ' ')"
[[ "$H" =~ ^[0-9a-fA-F]+$ && $(( ${#H}%2 )) -eq 0 ]]||{ echo "Hex inválido.";read -p "Enter...";continue; }
F="$F" H="$H" python3 - <<'PY' 2>&1|pg
import os
d=open(os.environ['F'],'rb').read();p=bytes.fromhex(os.environ['H']);i=0;t=0
while True:
 i=d.find(p,i)
 if i<0:break
 print(f"0x{i:08x}");i+=1;t+=1
print(f"--- total {t} ---")
PY
else
F="$F" Q="$Q" python3 - <<'PY' 2>&1|pg
import os
d=open(os.environ['F'],'rb').read();p=os.environ['Q'].encode();i=0;t=0
while True:
 i=d.find(p,i)
 if i<0:break
 print(f"0x{i:08x}");i+=1;t+=1
print(f"--- total {t} ---")
PY
fi
;;
45) echo "Filtro tempo real. Backspace apaga. Enter/ESC sai."
buf=""
while true;do
IFS= read -rsn1 K||break
case "$K" in
$'\x7f'|$'\x08')buf="${buf%?}" ;;
""|$'\x1b'|$'\n')break ;;
*)buf+="$K" ;;
esac
printf '\033[2J\033[H'
printf ">>> '%s'\n" "$buf"
[ -z "$buf" ]&&continue
F="$F" Q="$buf" python3 - <<'PY' 2>&1|head -25
import os
d=open(os.environ['F'],'rb').read();p=os.environ['Q'].encode();i=0;t=0
while True:
 i=d.find(p,i)
 if i<0:break
 print(f"  0x{i:08x}  {d[max(0,i-8):i+len(p)+8]!r}");i+=1;t+=1
 if t>=25:print("  ...");break
print("  (nenhum)" if t==0 else f"  matches: {t}")
PY
done
echo "Fim do filtro." ;;
46) F="$F" python3 - <<'PY' 2>&1|pg
import os
A='\033[34m';M='\033[31m';D='\033[32m';Y='\033[33m';R='\033[0m'
f=open(os.environ['F'],'rb');o=0
while True:
 c=f.read(16)
 if not c:break
 hx=[];ac=[]
 for b in c:
  if b==0x3b:hx.append(f"{A}3b{R}");ac.append(f"{A};{R}")
  elif b==0x3a:hx.append(f"{M}3a{R}");ac.append(f"{M}:{R}")
  elif b==0x20:hx.append(f"{D}20{R}");ac.append(f"{D}·{R}")
  elif b==0x09:hx.append(f"{Y}09{R}");ac.append(f"{Y}→{R}")
  elif b==0x0a:hx.append(f"{Y}0a{R}");ac.append(f"{Y}↵{R}")
  elif b==0x0d:hx.append(f"{Y}0d{R}");ac.append(f"{Y}⏎{R}")
  elif b==0x00:hx.append(f"{Y}00{R}");ac.append(f"{Y}∅{R}")
  else:hx.append(f"{b:02x}");ac.append(chr(b) if 32<=b<127 else '.')
 p=' '*(48-3*len(c))
 print(f"{o:08x}: {' '.join(hx)}{p} |{''.join(ac)}|")
 o+=len(c)
PY
;;
47|48|49|50|51|52) case "$OP" in
47)C=';';LB=';' ;;
48)C=':';LB=':' ;;
49)C=',.';LB=', e .' ;;
50)C='!';LB='!' ;;
51)C="'";LB="aspas simples" ;;
52)C='"';LB='aspas duplas' ;;
esac
F="$F" C="$C" LB="$LB" python3 - <<'PY' 2>&1|pg
import os
d=open(os.environ['F'],'rb').read();cs=set(os.environ['C'].encode());t=0
for i,b in enumerate(d):
 if b in cs:print(f"0x{i:08x}: 0x{b:02x}  '{chr(b)}'");t+=1
print(f"--- {os.environ['LB']}: total {t} ---")
PY
;;
53) F="$F" python3 - <<'PY' 2>&1|pg
import os,re
d=open(os.environ['F'],'rb').read()
p=re.compile(rb'(?:[\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf4][\x80-\xbf]{3}){4,}')
t=0
print("=== UTF-8 multibyte ===")
for m in p.finditer(d):
 try:
  s=m.group().decode('utf-8')
  if any(ord(c)>127 for c in s):
   print(f"0x{m.start():08x}: {s!r}");t+=1
   if t>=300:print("...");break
 except UnicodeDecodeError:pass
print(f"--- total {t} ---")
PY
;;
54) F="$F" python3 - <<'PY' 2>&1|pg
import os,re
d=open(os.environ['F'],'rb').read()
print("=== UTF-16LE ===")
for m in re.finditer(rb'(?:[\x20-\x7e]\x00){4,}',d):
 print(f"0x{m.start():08x}: {m.group().decode('utf-16le','replace')!r}")
print("\n=== UTF-16BE ===")
for m in re.finditer(rb'(?:\x00[\x20-\x7e]){4,}',d):
 print(f"0x{m.start():08x}: {m.group().decode('utf-16be','replace')!r}")
PY
;;
55) cat -- "$F" 2>&1|pg ;;
56) T="$(mktemp)";TF+=("$T")
xxd -- "$F" > "$T"
echo "Edite o dump em nano e saia pra aplicar."
nano "$T"
if cmp -s <(xxd -- "$F") "$T";then echo "Nada mudou."
elif xxd -r "$T" > "${T}.bin" 2>/dev/null&&[ -s "${T}.bin" ];then
bk>/dev/null;cp -- "${T}.bin" -- "$F";echo "Aplicado.";ck "$TA"
else echo -e "${V}Formato do dump inválido.${R}";fi
rm -f "$T" "${T}.bin";read -p "Enter..." ;;
57|58) C=';';[ "$OP" = "58" ]&&C=':'
cf "Remover TODOS '$C'."||continue
bk>/dev/null
F="$F" C="$C" python3 - <<PY
import os
$PY
f=os.environ['F'];c=os.environ['C'].encode();d=open(f,'rb').read();n=d.count(c)
salvar(f,d.replace(c,b''))
print(f"{n} removidos")
PY
ck "$TA";read -p "Enter..." ;;
59) read -p "Backup antes? [s/N] " r;[[ "$r" =~ ^[sS]$ ]]&&bk>/dev/null
nano -- "$F";ck "$TA";read -p "Enter..." ;;
0) if [ "$CF" -eq 1 ];then
read -p "Restaurar cores do Termux? [s/N] " r
if [[ "$r" =~ ^[sS]$ ]]&&[ -f "$HOME/.termux/colors.properties.bak" ];then
cp "$HOME/.termux/colors.properties.bak" "$HOME/.termux/colors.properties"
termux-reload-settings;echo "Restaurado."
fi
fi
echo "Saindo.";break ;;
*) echo "Inválida.";read -p "Enter..." ;;
esac
done
