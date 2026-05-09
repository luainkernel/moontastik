# MoonScript — Syntaxe, LDoc et pièges

Ce projet **évite le mot-clé `class`** de MoonScript. Le code compilé doit être
indépendant de la bibliothèque MoonScript (pas de `require "moon"`).

---

## Syntaxe de base

### Indentation significative

MoonScript utilise l'**espace blanc significatif** — l'indentation définit les
blocs. Utiliser des espaces (pas de tabulations) de façon cohérente.

### Mots-clés absents

- **Pas de `local`** — toutes les déclarations sont locales par défaut.
- **Pas de `end`** — les blocs sont fermés par retour au niveau d'indentation précédent.
- **Pas de `then`** — suit `if` directement sur la même ligne ou en indentation.
- **Pas de `do`** après `while`/`for` — mais `do` seul crée un bloc autonome.

```custos/.agents/moonscript.md#L1-1
if condition
  -- corps
else
  -- sinon

for i = 1, 10
  -- boucle

while true
  -- boucle

switch value
  when 1
    -- cas 1
  else
    -- défaut

a = 1
do
  b = 2
  a = 2
assert a == 2  -- OK
assert b == 2  -- Erreur : b n'est pas visible hors du bloc `do`
```

### Style fonctionnel (recommandé)

Préférer les modules exportant des fonctions :

```custos/.agents/moonscript.md#L1-1
parse_ip = (raw) ->
  -- ...

{ :parse_ip }
```

### Fat arrow et `@`

`=>` crée une fonction où `self` est lié automatiquement :

- `@` ≡ `self`
- `@prop` ≡ `self.prop`
- `(...) =>` ≡ `(self, ...) ->`

```custos/.agents/moonscript.md#L1-1
increment = (amount) =>
  @value += amount

obj = {
  value: 10
  increment: (amount) => @value += amount
}
```

### Objets avec `setmetatable`

Pour un objet avec état, utiliser une fonction factory :

```custos/.agents/moonscript.md#L1-1
MaTable = (prop1) ->
  obj = {
    value: prop1
    increment: (amount) => @value += amount
  }
  setmetatable obj, { __index: MaTable }
  obj

obj = MaTable 10
obj\increment 5
```

---

## LDoc

Toutes les fonctions doivent être documentées avec des commentaires LDoc :

```custos/.agents/moonscript.md#L1-1
--- Parse un en-tête IPv4 brut.
-- @tparam string raw   Données brutes du paquet
-- @tparam number offset Offset de départ de l'en-tête IP
-- @treturn table|nil   En-tête parsé ou nil en cas d'erreur
parse_ip = (raw, offset) ->
  -- ...
```

| Tag | Usage |
|-----|-------|
| `@tparam type name desc` | Paramètre typé |
| `@treturn type desc` | Valeur de retour typée |
| `@raise` | Exception pouvant être levée |

Types de base : `string`, `number`, `boolean`, `nil`, `table`, `function`,
`cdata`, `thread`. Paramètre optionnel : `@tparam table|nil [fields] desc`.

---

## Pièges de refactoring

### Destructuration avec alias

`{ :name }` est un raccourci pour `{ name: name }`. Dès que le nom local
diffère de la clé, le `:` préfixe est invalide :

```custos/.agents/moonscript.md#L1-1
-- FAUX : syntaxe invalide
{ :new: new_eth } = require "ipparse.l2.ethernet"

-- CORRECT : forme explicite
{ new: new_eth } = require "ipparse.l2.ethernet"

-- CORRECT : raccourci uniquement quand clé = nom local
{ :new } = require "ipparse.l2.ethernet"
```

### Fonctions de module vs méthodes : `.` pas `\`

Les modules exportant des fonctions simples (ex. `auth.nft_sessions`) doivent
être appelés avec `.`, pas `\`. L'opérateur `\` compile en syntaxe colon Lua
et injecte la table comme premier argument :

```custos/.agents/moonscript.md#L1-1
-- FAUX : nft_sessions exporte des fonctions, pas des méthodes
nft_sess\add_authenticated ip, ttl
-- Compile en : nft_sess.add_authenticated(nft_sess, ip, ttl)
-- → ip est la table du module → ip:find(":") plante

-- CORRECT :
nft_sess.add_authenticated ip, ttl
```

Signe de ce bug : `"attempt to call a nil value (field 'find')"` ou erreur
similaire sur une méthode string appelée sur ce qui devrait être une string.

### Appels multi-lignes : précalculer les arguments complexes

```custos/.agents/moonscript.md#L1-1
-- RISQUÉ : body peut être parsé comme argument de H.head
"<!DOCTYPE html>\n" .. H.html({ lang: "fr" },
  H.head { H.meta { charset: "UTF-8" } },
  body
)

-- SÛR : précalculer, utiliser la forme implicit-table
head = H.head { H.meta { charset: "UTF-8" } }
body = H.body { H.p "Content" }
"<!DOCTYPE html>\n" .. H.html lang: "fr", head, body
```

### `$` dans les strings MoonScript

Dans une string double-quotée MoonScript, `\$` compile en `\$` Lua, qui est
une séquence d'échappement invalide. Écrire `$` directement :

```custos/.agents/moonscript.md#L1-1
-- FAUX : \$p est un échappement invalide en Lua
"sed -n '/#{MARKER}/,\$p'"

-- CORRECT :
"sed -n '/#{MARKER}/,$p'"
```

### IPv6 dual-stack : conserver le pattern `socket.select`

```custos/.agents/moonscript.md#L1-1
-- FAUX : ne bind qu'IPv4, les clients IPv6 obtiennent "connection refused"
srv = socket.bind "*", port

-- CORRECT :
listen4 = make_server4 port  -- bind 0.0.0.0
listen6 = make_server6 port  -- bind ::
all_servers = { listen4 }
all_servers[#all_servers + 1] = listen6 if listen6
-- socket.select(all_servers, nil, timeout) pour accepter des deux
```

Un status 0 dans les DevTools du navigateur indique que la connexion a été
fermée avant tout réponse HTTP — généralement un crash dans le handler
capturé par `pcall`.

## Pièges de scope en MoonScript

### Variables dans les blocs de contrôle (`if`, `pcall`, etc.)

**Piège critique** : Les variables définies pour la première fois *dans* un bloc
`if`, `pcall`, `for`, ou autres structures de contrôle ne sont accessibles que
*dans* ce bloc. Elles sont indéfinies (nil) après le bloc.

```moonscript
-- ❌ INCORRECT : x est undefined après le if
if condition
  x = 10
print x  -- nil (erreur!)

-- ✓ CORRECT : déclarer avant le bloc
x = nil
if condition
  x = 10
print x  -- OK

-- ❌ INCORRECT : ctx est undefined après pcall
ok, err = pcall ->
  ctx = load_or_generate_sni "custos", cache
print ctx  -- nil (erreur!)

-- ✓ CORRECT : déclarer avant pcall
ctx = nil
ok, err = pcall ->
  ctx = load_or_generate_sni "custos", cache
-- ctx est maintenant accessible et non-nil
```

**Règle générale** : Si une variable doit être utilisée *après* un bloc de
contrôle, **la déclarer avant le bloc** (même si la déclaration est `var = nil`).

### Portée des boucles

Les variables de boucle (`for i`, `for k, v`) sont toujours locales à la boucle.
Les variables *modifiées* dans une boucle restent accessibles après.

```moonscript
x = 0
for i = 1, 10
  x = x + i  -- x accessible, modifiable
print x  -- 55 (OK)

for i = 1, 10
  y = i  -- y créée dans la boucle
print y  -- 10 (OK, persist après boucle)
```

### Problème avec les closures et `pcall`

MoonScript autorise les closures, mais `pcall` crée une portée supplémentaire.
Les variables créées dans le callback `pcall` ne survivent pas à la fin du callback.

```moonscript
-- ❌ PROBLÈME : ctx échappé du callback pcall
ok = pcall ->
  ctx = create_context()
ssl.wrap socket, ctx  -- ctx est nil!

-- ✓ SOLUTION : déclarer ctx avant
ctx = nil
ok = pcall ->
  ctx = create_context()
ssl.wrap socket, ctx  -- OK
```

### Matrice de test pour les modifications du worker AUTH

Toujours tester toutes les combinaisons après une modification du worker AUTH :

| Test | Commande | Attendu |
|------|----------|---------|
| GET / IPv4 | `curl -v http://<ip4>:33443/` | 200 OK + formulaire HTML |
| GET / IPv6 | `curl -v http://[<ip6>]:33443/` | 200 OK + formulaire HTML |
| POST /login IPv4 | `curl -X POST -d "user=..." -d "password=..."` | 200 OK ou 401 |
| POST /login IPv6 | idem sur IPv6 | 200 OK ou 401 |
| TLS handshake | navigateur ou `openssl s_client` | complète sans erreur |
