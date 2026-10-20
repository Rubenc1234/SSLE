How to run:
```bash
cd ~/.../P1
chmod +x infra/*.sh
./infra/build-base.sh     # uma vez
./infra/deploy.sh
./infra/test.sh
```

Verifications:
```bash
incus exec $(incus list -c n -f csv | grep ^registry) -- curl -s "localhost:5050/services?type=sensor"
incus exec <contentor-storage> -- tail -f /var/log/ssle/access.log
incus exec <contentor-storage> -- systemctl status ssle
```

Notes:
```
Depois de editar um .py, voltar a correr ./infra/deploy.sh. Recriar tudo e a BD fica limpa.
```
