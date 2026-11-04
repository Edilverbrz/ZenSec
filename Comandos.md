### comandos que debe ejecutar el proyecto para tener exito.

sudo openfortivpn -c ~/vpn.conf -u usuario *coneccion vpn*

mkdir carpeta
cd carpeta

nmap -sV --script Vuln -p- -T4 -o nmap_vuln.txt direccion_ip
nmap -sV -oN puertostodos.txt direccion_ip
nmap -p listado_de_puertos -oN puertosespecificos.txt direccion_ip


dirb http://direccion_ip -o dirb.txt
dirb https://direccion_ip -o dirbs.txt


nikto -h direccion_ip -o nikto.txt
nikto -h direccion_ip -p listado_de_puertos -o niktopuertos.txt


sqlmap -u http://direccion_ip --batch > sqlmap.txt
sqlmap -u https://direccion_ip --batch > sqlmaps.txt

sqlmap -u http://direccion_ip --crawl=2 --forms --batch --dbms=postgresql --level=3 --risk=2 > sql_crawl2.txt
sqlmap -u https://direccion_ip --crawl=2 --forms --batch --dbms=postgresql --level=3 --risk=2 > sql_crawl2s.txt

sqlmap -u http://direccion_ip --batch > sqlmapurl.tx
sqlmap -u https://direccion_ip --batch > sqlmapurls.tx

curl -Iv direccion_ip -o curl.txt

nuclei -u direccion_ip -severity critical,high -o nuclei.txt
nuclei -u direccion_ip -tags panel,login,default-login -o nucleitags.txt

wapiti -u direccion_ip -o wapiti.txt
wapiti -u https://direccion_ip -o wapitihttps.txt
wapiti -u http://direccion_ip -o wapitihttp.txt
