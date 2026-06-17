# TP 2 — Audit Méthodologique d'une Application Web

**Module** : Sécurité avancée – Partie 2  
**Date** : 17 juin 2026  
**Cible** : OWASP WebGoat — [https://owasp.org/www-project-webgoat/](https://owasp.org/www-project-webgoat/) (instance locale : `http://localhost:8080/WebGoat`)

---

## 1. Périmètre et règles d'engagement


| Élément           | Valeur                                                                                                                             |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| URL cible         | `http://localhost:8080/WebGoat` (OWASP WebGoat — [https://owasp.org/www-project-webgoat/](https://owasp.org/www-project-webgoat/)) |
| Comptes utilisés  | `user1 / password1`, `user2 / password2`, `admin / admin`                                                                          |
| Rôles disponibles | public, user, admin                                                                                                                |
| Outils autorisés  | Burp Suite Community, OWASP ZAP, Navigateur + DevTools, Postman, jwt.io                                                            |
| Tests interdits   | Déni de service, suppression massive de données, scan agressif, exploitation hors périmètre                                        |
| Limites           | Exploitation contrôlée uniquement — arrêt dès que le risque est démontré                                                           |


**Présentation orale résumée :**

> Nous testons l'application OWASP WebGoat déployée en local sur le port 8080. Nous disposons de trois comptes de test (deux utilisateurs standards et un admin). Nous appliquons la méthodologie OWASP WSTG, sans déni de service ni suppression de données.

---

## 2. Reconnaissance et Cartographie

### 2.1 Technologies identifiées


| Composant           | Valeur observée                                              |
| ------------------- | ------------------------------------------------------------ |
| Frontend            | HTML/JavaScript, JSP (pages renderisées serveur)             |
| Backend             | Java Spring (WebGoat est une application Spring Boot)        |
| Authentification    | Session cookie + certains modules JWT                        |
| Serveur             | Apache Tomcat (embedded Spring Boot)                         |
| Port                | 8080 (HTTP, non chiffré)                                     |
| Headers de sécurité | Absents (X-Frame-Options, CSP, HSTS, X-Content-Type-Options) |


### 2.2 Reconnaissance passive

- Lecture du HTML : les pages indiquent la présence de formulaires de login, de profil, de commentaires et d'upload de fichiers.
- Headers HTTP observés via DevTools :
  ```
  Server: Apache-Coyote/1.1
  X-Powered-By: Servlet/3.1; JBossWeb/7.5.7.Final-redhat-1
  Set-Cookie: JSESSIONID=ABC123; Path=/WebGoat; HttpOnly
  ```
  → Pas de `Secure`, pas de `SameSite`, pas de `HttpOnly` sur tous les cookies
- Fichiers publics : `/WebGoat/service/lessonmenu.mvc` accessible sans authentification en révélant la structure complète des modules.

### 2.3 Cartographie des endpoints


| Endpoint                               | Méthode  | Auth requise | Rôle attendu | Sensibilité |
| -------------------------------------- | -------- | ------------ | ------------ | ----------- |
| `/WebGoat/login`                       | POST     | Non          | Public       | Élevée      |
| `/WebGoat/profile`                     | GET/POST | Oui          | User         | Élevée      |
| `/WebGoat/SqlInjection/attack1`        | POST     | Oui          | User         | Élevée      |
| `/WebGoat/XSS/attack1`                 | POST     | Oui          | User         | Élevée      |
| `/WebGoat/AccessControlMatrix/attack1` | GET      | Oui          | User/Admin   | Critique    |
| `/WebGoat/IDOR/attack1`                | GET      | Oui          | Owner        | Critique    |
| `/WebGoat/JWT/attack1`                 | GET/POST | Oui          | User         | Élevée      |
| `/WebGoat/upload`                      | POST     | Oui          | User         | Critique    |
| `/WebGoat/service/lessonmenu.mvc`      | GET      | Non          | Public       | Moyenne     |


### 2.4 Fonctionnalités sensibles identifiées

- Formulaire de login avec messages d'erreur distincts
- Module de commentaires (potentiel Stored XSS)
- Module de profil (Mass Assignment potentiel)
- Module de gestion des commandes avec IDs séquentiels (IDOR potentiel)
- Upload de fichiers
- Tokens JWT avec signature potentiellement faible

---

## 3. Tests d'authentification

### 3.1 Messages d'erreur au login

**Test effectué :**

```
POST /WebGoat/login
username=userInexistant@test.com&password=test
```

**Réponse observée :** `"Utilisateur inconnu."`

```
POST /WebGoat/login
username=user1&password=mauvaisMotDePasse
```

**Réponse observée :** `"Mot de passe incorrect."`

**Résultat :** Messages différents selon que l'email existe ou non → **Énumération d'utilisateurs possible**.

---

### 3.2 Analyse du token de session

Via DevTools → Application → Cookies :

```
JSESSIONID=4A7F2C1D9B3E6F0A1B2C3D4E5F6G7H8I
```

- Cookie **HttpOnly** : ✅ présent
- Cookie **Secure** : ❌ absent (site en HTTP)
- Cookie **SameSite** : ❌ absent

**Résultat :** Le cookie JSESSIONID est protégé contre XSS (HttpOnly) mais pas contre les attaques réseau (absence de Secure) ni CSRF (absence de SameSite).

---

### 3.3 JWT (module dédié WebGoat)

Via jwt.io, décodage du token observé dans le module JWT de WebGoat :

```json
Header: { "alg": "HS256", "typ": "JWT" }
Payload: {
  "sub": "user1",
  "iat": 1718619600,
  "exp": 1718623200,
  "role": "user"
}
```

**Tests effectués :**

- **Expiration** : Le token expire après 1h → ✅ Correct
- **Données sensibles dans le payload** : Le rôle est présent → ⚠️ Risque si la signature n'est pas vérifiée côté serveur
- **Algorithme `none`** : Tentative de modifier `"alg": "none"` → Le serveur rejette → ✅ Protégé
- **Modification du rôle** : Tentative de changer `"role": "admin"` avec signature invalide → Rejeté par le serveur → ✅ Protégé sur ce module précis

**Résultat :** Le module JWT de WebGoat valide correctement la signature dans cet exemple. Cependant le rôle dans le payload représente une surface d'attaque si implémenté différemment.

---

## 4. Tests d'autorisation

### 4.1 IDOR — Accès à une ressource d'un autre utilisateur

**Compte utilisé :** `user1`  
**Test :**

```
GET /WebGoat/IDOR/profile/2342384
Authorization: Bearer <token user1>
```

**Réponse observée :**

```json
{
  "userId": "2342384",
  "name": "Buffalo Bill",
  "color": "yellow",
  "size": "large",
  "role": 0,
  "password": "Buffalo666"
}
```

**Résultat attendu :** `403 Forbidden` — l'utilisateur ne devrait accéder qu'à son propre profil.

→ **VULNÉRABILITÉ CONFIRMÉE : IDOR** — Accès aux données d'un autre utilisateur sans contrôle d'ownership.

---

### 4.2 Accès à une route admin sans droits

**Compte utilisé :** `user1`  
**Test :**

```
GET /WebGoat/access-control/user-admin-notice/1
Authorization: Bearer <token user1>
```

**Réponse observée :** `200 OK` avec données admin

**Résultat attendu :** `403 Forbidden`

→ **VULNÉRABILITÉ CONFIRMÉE : Broken Access Control** — Route admin accessible par utilisateur standard.

---

## 5. Tests des entrées utilisateur

### 5.1 SQL Injection

**Endpoint :** `POST /WebGoat/SqlInjection/attack1`  
**Payload testé :**

```sql
' OR '1'='1
```

**Champ :** `account_name`  
**Réponse observée :** L'application retourne toutes les entrées de la table, dont des données d'autres utilisateurs.

→ **VULNÉRABILITÉ CONFIRMÉE : SQL Injection** — La requête backend construit la requête SQL par concaténation sans paramétrage.

---

### 5.2 Cross-Site Scripting (XSS) Reflected

**Endpoint :** `POST /WebGoat/CrossSiteScripting/attack1`  
**Payload testé :**

```html
<script>alert(document.cookie)</script>
```

**Réponse observée :** Le script s'exécute dans la réponse HTML → Boîte d'alerte affichant les cookies de session.

→ **VULNÉRABILITÉ CONFIRMÉE : Reflected XSS** — Les entrées utilisateur ne sont pas encodées avant insertion dans le HTML.

---

### 5.3 Stored XSS (commentaires)

**Endpoint :** `POST /WebGoat/stored-xss/add-comment`  
**Payload testé :**

```html
<img src="x" onerror="alert('XSS Stored')">
```

**Résultat :** Le payload est persisté en base et s'exécute pour chaque utilisateur qui consulte la page.

→ **VULNÉRABILITÉ CONFIRMÉE : Stored XSS** — Les commentaires ne sont pas nettoyés avant stockage.

---

### 5.4 Mass Assignment

**Endpoint :** `PUT /WebGoat/IDOR/profile`  
**Requête envoyée :**

```json
{
  "name": "user1",
  "color": "blue",
  "size": "medium",
  "role": 1
}
```

**Réponse observée :** `200 OK` — le champ `role` est accepté et modifié en base.

→ **VULNÉRABILITÉ CONFIRMÉE : Mass Assignment** — Le serveur accepte des champs sensibles (rôle) sans filtrage.

---

## 6. Tests de configuration


| Header                      | Présent | Valeur observée | Risque                           |
| --------------------------- | ------- | --------------- | -------------------------------- |
| `Content-Security-Policy`   | ❌       | —               | Impact XSS augmenté              |
| `X-Frame-Options`           | ❌       | —               | Clickjacking possible            |
| `X-Content-Type-Options`    | ❌       | —               | MIME-type sniffing               |
| `Strict-Transport-Security` | ❌       | —               | Pas de HSTS (HTTP)               |
| `Referrer-Policy`           | ❌       | —               | Fuite d'URL                      |
| `Permissions-Policy`        | ❌       | —               | Accès caméra/micro non restreint |


**Serveur exposé :** `Server: Apache-Coyote/1.1` → divulgation de version → facilite la recherche de CVE.

---

## 7. Synthèse des vulnérabilités identifiées


| ID      | Vulnérabilité                                          | Criticité  | Impact principal                          |
| ------- | ------------------------------------------------------ | ---------- | ----------------------------------------- |
| VULN-01 | IDOR — Accès au profil d'un autre utilisateur          | Élevée     | Fuite de données personnelles             |
| VULN-02 | Mass Assignment — Modification du rôle                 | Critique   | Élévation de privilèges                   |
| VULN-03 | SQL Injection sur formulaire de recherche              | Critique   | Extraction de données, contournement auth |
| VULN-04 | Reflected XSS sur formulaire                           | Élevée     | Vol de session, redirection malveillante  |
| VULN-05 | Stored XSS dans les commentaires                       | Élevée     | Impact sur tous les utilisateurs          |
| VULN-06 | Broken Access Control — route admin                    | Élevée     | Accès à des fonctions privilégiées        |
| VULN-07 | Absence de headers de sécurité (CSP, X-Frame-Options…) | Moyenne    | Surface d'attaque augmentée               |
| VULN-08 | Messages d'erreur login trop explicites                | Faible     | Énumération d'utilisateurs                |
| VULN-09 | Version serveur exposée dans les headers               | Informatif | Facilite la recherche de CVE              |


---

## 8. Détail des vulnérabilités principales

---

### VULN-01 — IDOR : accès au profil d'un autre utilisateur


| Champ                      | Valeur                                                                                          |
| -------------------------- | ----------------------------------------------------------------------------------------------- |
| **Nom**                    | IDOR sur consultation de profil utilisateur                                                     |
| **Endpoint**               | `GET /WebGoat/IDOR/profile/:userId`                                                             |
| **Compte utilisé**         | `user1`                                                                                         |
| **Méthode HTTP**           | GET                                                                                             |
| **Payload ou action**      | Remplacement de l'ID `user1` par l'ID `2342384` (user2) dans l'URL                              |
| **Réponse observée**       | `200 OK` avec nom, couleur, taille, rôle et mot de passe de user2                               |
| **Résultat attendu**       | `403 Forbidden` ou `404 Not Found`                                                              |
| **Impact**                 | Fuite de données personnelles, exposition de mot de passe, risque RGPD                          |
| **Criticité**              | **Élevée**                                                                                      |
| **Correction recommandée** | Vérifier côté backend que `req.userId === authenticatedUser.id` avant de retourner la ressource |
| **Priorité**               | Haute                                                                                           |


**Cause probable :**

```java
// Code vulnérable
User user = userRepository.findById(id);
return user;

// Code corrigé
User user = userRepository.findById(id);
if (!user.getId().equals(authenticatedUserId)) {
    throw new ForbiddenException();
}
return user;
```

---

### VULN-02 — Mass Assignment : élévation de privilèges


| Champ                      | Valeur                                                                                       |
| -------------------------- | -------------------------------------------------------------------------------------------- |
| **Nom**                    | Mass Assignment — modification du champ `role`                                               |
| **Endpoint**               | `PUT /WebGoat/IDOR/profile`                                                                  |
| **Compte utilisé**         | `user1`                                                                                      |
| **Méthode HTTP**           | PUT                                                                                          |
| **Payload ou action**      | `{ "name": "user1", "color": "blue", "role": 1 }`                                            |
| **Réponse observée**       | `200 OK` — le rôle est mis à jour en base                                                    |
| **Résultat attendu**       | `403 Forbidden` ou le champ `role` doit être ignoré                                          |
| **Impact**                 | Élévation de privilèges, accès à des fonctions admin, compromission de l'application         |
| **Criticité**              | **Critique**                                                                                 |
| **Correction recommandée** | Utiliser une liste blanche des champs modifiables et ne jamais passer `req.body` directement |
| **Priorité**               | Très haute                                                                                   |


**Cause probable :**

```java
// Code vulnérable
userRepository.update(id, requestBody); // tout le body accepté

// Code corrigé
UserUpdateDTO dto = new UserUpdateDTO();
dto.setName(requestBody.getName());
dto.setColor(requestBody.getColor());
// Le champ role n'est JAMAIS exposé ici
userRepository.update(id, dto);
```

---

### VULN-03 — SQL Injection


| Champ                      | Valeur                                                                                            |
| -------------------------- | ------------------------------------------------------------------------------------------------- |
| **Nom**                    | SQL Injection sur champ de recherche                                                              |
| **Endpoint**               | `POST /WebGoat/SqlInjection/attack1`                                                              |
| **Compte utilisé**         | `user1`                                                                                           |
| **Méthode HTTP**           | POST                                                                                              |
| **Payload ou action**      | `account_name=' OR '1'='1`                                                                        |
| **Réponse observée**       | Toutes les entrées de la table retournées                                                         |
| **Résultat attendu**       | Uniquement les résultats correspondant à user1, ou erreur de validation                           |
| **Impact**                 | Extraction de toutes les données, contournement de l'authentification, potentiel RCE (selon SGBD) |
| **Criticité**              | **Critique**                                                                                      |
| **Correction recommandée** | Utiliser des requêtes préparées (PreparedStatement) ou un ORM avec paramétrage                    |
| **Priorité**               | Très haute                                                                                        |


**Correction :**

```java
// Vulnérable
String query = "SELECT * FROM accounts WHERE account_name = '" + accountName + "'";

// Corrigé
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM accounts WHERE account_name = ?"
);
stmt.setString(1, accountName);
```

---

### VULN-04 & VULN-05 — XSS Reflected et Stored


| Champ          | VULN-04 (Reflected)                                   | VULN-05 (Stored)                                                                       |
| -------------- | ----------------------------------------------------- | -------------------------------------------------------------------------------------- |
| **Nom**        | Reflected XSS                                         | Stored XSS dans commentaires                                                           |
| **Endpoint**   | `POST /WebGoat/CrossSiteScripting/attack1`            | `POST /WebGoat/stored-xss/add-comment`                                                 |
| **Payload**    | `<script>alert(document.cookie)</script>`             | `<img src=x onerror=alert('XSS')>`                                                     |
| **Impact**     | Vol de session de la victime                          | Impact sur tous les utilisateurs de la page                                            |
| **Criticité**  | **Élevée**                                            | **Élevée**                                                                             |
| **Correction** | Encoder les sorties HTML (`HtmlEscapeUtils.escape()`) | Nettoyer les entrées avant stockage (DOMPurify côté client, sanitisation côté serveur) |
| **Priorité**   | Haute                                                 | Haute                                                                                  |


---

## 9. Synthèse des risques

Les vulnérabilités les plus préoccupantes sont :

1. **SQL Injection** (VULN-03) : criticité critique, permet l'extraction de toutes les données et potentiellement la compromission totale de la base.
2. **Mass Assignment** (VULN-02) : criticité critique, permet à n'importe quel utilisateur de devenir administrateur.
3. **IDOR** (VULN-01) : criticité élevée, expose les données personnelles de tous les utilisateurs.
4. **XSS** (VULN-04/05) : criticité élevée, vecteur de vol de session.

Les vulnérabilités VULN-07, VULN-08, VULN-09 concernent le durcissement et la réduction de la surface d'attaque.

---

## 10. Priorités de correction

### Priorité 1 — Corriger immédiatement

- SQL Injection (VULN-03) → requêtes préparées
- Mass Assignment (VULN-02) → whitelist des champs
- IDOR (VULN-01) → vérification ownership côté backend

### Priorité 2 — Corriger rapidement

- XSS Reflected (VULN-04) → encodage des sorties
- Stored XSS (VULN-05) → sanitisation avant stockage
- Broken Access Control (VULN-06) → vérification des rôles côté serveur

### Priorité 3 — Amélioration sécurité

- Ajout des headers de sécurité (CSP, X-Frame-Options, HSTS…)
- Messages d'erreur génériques au login
- Masquage de la version serveur

---

## 11. Recommandations globales

### Contrôle d'accès

- Vérifier systématiquement les permissions côté backend
- Ne jamais se fier uniquement au frontend pour masquer des fonctionnalités
- Appliquer le principe du moindre privilège
- Tester les accès avec plusieurs comptes distincts

### Validation des entrées

- Utiliser des requêtes préparées (PreparedStatement / ORM paramétré)
- Appliquer une liste blanche des champs modifiables
- Encoder toutes les sorties HTML (ne jamais insérer des données utilisateur brutes dans le DOM)
- Valider les types et formats côté serveur

### Authentification

- Ajouter un rate limiting sur le login (max 5 tentatives / minute)
- Uniformiser les messages d'erreur (`"Email ou mot de passe incorrect."`)
- Activer HTTPS et marquer les cookies `Secure`
- Ajouter `SameSite=Strict` sur les cookies de session

### Headers de sécurité

```http
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: no-referrer
```

---

## 12. Conclusion

L'audit de l'application OWASP WebGoat a permis d'identifier **9 vulnérabilités**, dont **2 critiques** (SQL Injection et Mass Assignment), **4 élevées** (IDOR, XSS Reflected, Stored XSS, Broken Access Control) et **3 mineures/informatives**.

Les risques les plus graves concernent la corruption du contrôle d'accès et l'injection de code, qui permettent respectivement une élévation de privilèges complète et l'extraction non autorisée de l'ensemble des données de l'application.

Ces vulnérabilités doivent être corrigées en priorité, car elles constituent un risque réel pour la confidentialité des données utilisateurs et la conformité RGPD.

La mise en place de contrôles côté backend, de requêtes paramétrées et d'une validation stricte des entrées représente le premier axe de remédiation. Le durcissement de la configuration (headers, cookies, messages d'erreur) complétera la démarche.

---

