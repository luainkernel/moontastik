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
  `build/guest-modules-<version>/`) car vng le bind-monte en lecture seule par
  défaut ; lunatik et ipparse s'y installent, puis `modprobe lunatik`, `make
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
tools/vmtest/run.sh             # suite complète (ipparse + lunatik)
tools/vmtest/run.sh --lunatik   # suite complète de lunatik seule
tools/vmtest/run.sh --all       # toutes les versions de KERNEL_VERSIONS
tools/vmtest/run.sh --all --lunatik  # les deux options sont cumulables
# ou, depuis la racine :
make vm-test
```

`--all` exécute le script complet pour chaque noyau de `KERNEL_VERSIONS`
(6.6, 6.12, 6.18, 7.3), continue après un échec et affiche en fin de course un
tableau version → code de retour ; le code de sortie global est non nul si au
moins une version échoue. Chaque version a ses propres artefacts
(`linux-<version>`, `guest-modules-<version>`, `kernelrelease-<version>`) et
son propre répertoire scratch, elles peuvent donc cohabiter dans le cache.

`--lunatik` remplace la suite ipparse par `lunatik test` dans la VM (lunatik
est installé avec Lua 5.5). Les modules de lunatik sont compilés dans l'arbre
source : `build-lunatik.sh` fait un `make clean` avant chaque version pour ne
pas réutiliser des objets compilés contre un autre noyau.

Premier lancement : ~15-20 min par noyau (ensuite caché dans
`tools/vmtest/build/`).

Variables utiles :

- `LUNATIK_SRC=/chemin/vers/lunatik` — tester contre un checkout local au lieu
  du clone épinglé ;
- `VMTEST_BUILD_DIR` — déplacer le cache de build ;
- `VMTEST_BYTECODE=0` — ne pas rejouer la suite noyau en bytecode (par défaut,
  la VM réinstalle ipparse avec `BYTECODE=1` après la passe source et relance
  la suite, si `lunatic` est disponible) ;
- `KERNEL_VERSION=<version>` — noyau ciblé (défaut : `versions.env`), p. ex.
  `KERNEL_VERSION=6.18.62 tools/vmtest/run.sh --smoke` pour réutiliser un
  build existant ; `KERNEL_VERSIONS` (liste) pilote `--all`.

`VMTEST_BUILD_DIR` et `LUNATIK_SRC` sont résolus en chemins absolus et
transmis à l'invité, qui monte le système de fichiers de l'hôte en lecture
seule : un cache situé hors du dépôt (par exemple `tools/vmtest/build` en
lien symbolique vers un cache partagé) fonctionne tel quel. Chaque lancement
utilise son propre répertoire temporaire pour rapatrier sortie/code de retour,
donc deux `run.sh` simultanés ne se marchèvent pas (`VMTEST_RW_DIR` permet de
forcer un répertoire commun, à réserver à un usage séquentiel).

## Fichiers

| Fichier | Rôle |
|---|---|
| `versions.env` | Versions épinglées (noyaux, dépôt/étiquette/commit lunatik) |
| `kernel.fragment` | Options de config noyau requises par Lunatik |
| `flake.nix` | Toolchain reproductible (gcc, qemu, luajit, moonscript…) |
| `ensure-vng.sh` | Installe virtme-ng dans `.venv/` (absent de nixpkgs) |
| `kernel.sh` | Télécharge + compile le noyau épinglé (idempotent) |
| `build-lunatik.sh` | Clone épinglé + build des modules contre ce noyau |
| `guest-test.sh` | S'exécute **dans** la VM : install + tests ipparse |
| `guest-lunatik.sh` | S'exécute **dans** la VM : suite `lunatik test` |
| `run.sh` | Point d'entrée (`--all`, `--lunatik`, `--smoke`) |
