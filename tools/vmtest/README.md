# vmtest — environnement de test unifié en VM

Exécute la suite de tests complète (espace utilisateur **et** noyau/Lunatik)
dans un microVM [virtme-ng](https://github.com/arighi/virtme-ng) sur un noyau
LTS épinglé, identique en local et en CI GitHub.

## Principe

- virtme-ng démarre un VM QEMU en quelques secondes : **pas d'image système**,
  le système de fichiers de l'hôte est monté en lecture seule avec un overlay
  en écriture. La chaîne de compilation est celle du shell Nix, dedans comme
  dehors.
- Le noyau (version dans `versions.env`) est compilé une fois avec la config
  minimale de virtme-ng + `kernel.fragment` (options crypto requises par
  Lunatik), puis mis en cache.
- Lunatik est cloné épinglé (`versions.env`) et compilé contre ce noyau,
  **hors VM** (même toolchain, pas de surcoût de virtualisation).
- Dans la VM : `/lib/modules` est un montage 9p inscriptible (adossé à
  `build/guest-modules/`) car vng le bind-monte en lecture seule par défaut ;
  lunatik et ipparse s'y installent, puis `modprobe lunatik`, `make
  test-nobuild` (LuaJIT) et `make test-lunatik-run`. Les cibles `-nobuild`
  réutilisent les `.lua` compilés sur l'hôte (l'arbre source est monté en
  lecture seule).
- Le code de sortie est rapatrié par fichier via un répertoire partagé
  (la propagation native de vng n'est pas fiable sans udev), et les `FAIL`
  des tests kernel sont détectés dans dmesg par `test-lunatik-run`.

## Utilisation

```bash
nix develop ./tools/vmtest      # ou direnv
tools/vmtest/run.sh --smoke     # boot + vérification du noyau (~1 min après build)
tools/vmtest/run.sh             # suite complète
# ou, depuis la racine :
make vm-test
```

Premier lancement : ~15-20 min (compilation du noyau, ensuite caché dans
`tools/vmtest/build/`).

Variables utiles :

- `LUNATIK_SRC=/chemin/vers/lunatik` — tester contre un checkout local au lieu
  du clone épinglé ;
- `VMTEST_BUILD_DIR` — déplacer le cache de build.

## Fichiers

| Fichier | Rôle |
|---|---|
| `versions.env` | Versions épinglées (noyau, dépôt/branche lunatik) |
| `kernel.fragment` | Options de config noyau requises par Lunatik |
| `flake.nix` | Toolchain reproductible (gcc, qemu, luajit, moonscript…) |
| `ensure-vng.sh` | Installe virtme-ng dans `.venv/` (absent de nixpkgs) |
| `kernel.sh` | Télécharge + compile le noyau épinglé (idempotent) |
| `build-lunatik.sh` | Clone épinglé + build des modules contre ce noyau |
| `guest-test.sh` | S'exécute **dans** la VM : install + tests |
| `run.sh` | Point d'entrée (orchestration + `--smoke`) |
