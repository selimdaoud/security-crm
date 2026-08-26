# Security CRM / SED Dashboard — Document de transmission pour une IA

> Historical French handoff. Paths have been updated to the reorganized
> repository. For current English navigation, start with
> [`../../README.md`](../../README.md).

Dernière mise à jour : 31 juillet 2026  
Répertoire local : `/Users/sdaoud/Library/CloudStorage/OneDrive-OracleCorporation/CODE/Securtiy CRM`

## 1. Objet de ce document

Ce document donne à une IA ou à un nouveau développeur suffisamment de contexte pour continuer le projet sans dépendre de l’historique de conversation.

Il distingue trois niveaux :

- **Implémenté localement** : du code existe réellement dans ce dépôt.
- **Observé dans APEX** : la configuration provient d’un export ou d’une définition de page fournie par l’utilisateur.
- **Planifié** : la fonctionnalité est décrite dans les documents, mais son code n’est pas encore terminé.

Ne jamais considérer un élément décrit dans `docs/product/mvp.md`, `docs/operations/deployment-next-steps.md` ou `docs/architecture/sql-implementation-plan.md` comme implémenté sans vérifier le fichier SQL ou l’export APEX correspondant.

## 2. Résumé du projet

Le projet est une application Oracle APEX de gestion de la relation client orientée sécurité. Son nom historique est `sed-dashboard`; le dossier est nommé `Security CRM`.

L’application doit permettre aux Security Advisors de :

- visualiser leur portefeuille de clients ;
- comprendre rapidement l’état de la relation avec chaque client ;
- maintenir les informations du client, ses contacts et son équipe Oracle ;
- inventorier les produits et services Oracle utilisés par le client ;
- enregistrer les interactions, reviews et actions ;
- suivre les événements et dossiers de sécurité ;
- identifier les clients potentiellement impactés par une publication de sécurité ;
- préparer et suivre les campagnes de notification ;
- conserver un score de santé actuel et son historique ;
- générer des alertes opérationnelles ;
- plus tard, utiliser une IA pour produire une analyse de sécurité fondée sur des preuves.

Le centre du modèle est le **client**. La page principale de détail s’appelle **Customer 360**.

## 3. Utilisateurs et logique métier

### 3.1 Utilisateur principal

Le premier persona est le **Security Advisor**. Il est responsable d’un portefeuille de clients et doit :

- examiner les clients nécessitant de l’attention ;
- travailler les actions ouvertes ;
- préparer les prochains contacts et reviews ;
- maintenir les données sur l’environnement Oracle du client ;
- analyser les événements de sécurité ;
- coordonner les notifications et remédiations ;
- comprendre et expliquer l’évolution du score Health.

### 3.2 Autres acteurs prévus

Le modèle permet aussi de représenter :

- Customer Success Managers ;
- commerciaux CSS ;
- Solution Architects ;
- responsables et sponsors exécutifs ;
- autres membres de l’équipe de compte Oracle ;
- contacts externes chez le client.

Tous les utilisateurs internes sont actuellement stockés dans `internal_users`. Il n’existe pas encore de modèle d’autorisation APEX complet dans le dépôt.

### 3.3 Règles MVP importantes

- Un client possède un **Security Advisor principal** obligatoire.
- Le Security Advisor principal est stocké directement dans `customers.primary_security_advisor_user_id`.
- L’équipe de compte étendue est stockée dans `oracle_account_team_members`.
- Le score Health actuel est stocké directement dans `customers`.
- L’historique Health doit être stocké dans `relationship_health_snapshots`, mais cette table n’est pas encore implémentée.
- Les valeurs contrôlées utilisent des tables de lookup, pas des textes libres.
- Les changements sensibles proposés par une future IA ne doivent pas être appliqués automatiquement sans validation humaine.

## 4. Architecture technique

### 4.1 Technologies

- Base de données Oracle.
- SQL et PL/SQL.
- Oracle APEX avec Universal Theme.
- Régions APEX : Dynamic Content, Classic Report, Interactive Report, Tabs Container.
- HTML produit par PL/SQL avec `htp.p`.
- CSS global dans `apex/static/dashboard.css`.
- Pas de framework JavaScript applicatif identifié.
- Pas de build Node ou de tests automatisés identifiés.

### 4.2 Couches

1. **Données**
   - tables de lookup ;
   - tables métier ;
   - contraintes et index ;
   - vues de reporting.

2. **Logique métier**
   - packages PL/SQL prévus pour Health, dossiers de sécurité, campagnes et alertes ;
   - ces packages sont encore à implémenter.

3. **Présentation**
   - pages Oracle APEX ;
   - SQL de rapports ;
   - régions Dynamic Content ;
   - CSS Universal Theme personnalisé.

4. **Sources de sécurité**
   - table locale `security_publications` prévue pour les publications Oracle CPU, CSPU et Security Alerts ;
   - source envisagée : flux RSS officiel Oracle Security.

5. **IA future**
   - récupération de données internes et de publications fiables ;
   - production d’une évaluation structurée ;
   - conservation des preuves et du statut de revue humaine.

### 4.3 État du dépôt

Le dossier local ne contient pas de dépôt Git détectable à sa racine. Il est synchronisé dans OneDrive. Une IA ne doit donc pas supposer qu’elle peut utiliser un historique Git, créer une branche ou restaurer un fichier avec Git.

L’état réellement déployé dans APEX ou dans la base Oracle n’est pas entièrement vérifiable depuis les fichiers locaux. Avant une migration, comparer le code local avec :

- l’export courant de l’application APEX ;
- les objets présents dans le schéma Oracle ;
- les fichiers statiques réellement chargés dans Shared Components.

Informations d’environnement encore inconnues dans le dépôt :

- identifiant numérique de l’application APEX ;
- version exacte d’Oracle APEX et de la base ;
- noms du Workspace et du schéma de parsing ;
- URL des environnements ;
- schéma d’authentification actif ;
- liste complète des pages déployées ;
- rôles et Authorization Schemes existants.

Ne jamais inventer ces valeurs. Les demander à l’utilisateur ou les lire depuis un export APEX récent.

## 5. Carte des fichiers

### 5.1 Fichiers principaux

| Fichier | Rôle | État |
|---|---|---|
| `apex/static/dashboard.css` | CSS global du Dashboard, Portfolio, Customer 360 et Security Events | Implémenté |
| `apex/components/portfolio/report.sql` | Requête actuelle du rapport Portfolio avec liens Customer et Customer 360 | Implémenté |
| `apex/exports/legacy/sed-dashboard-page-1.apx` | Export texte de la page 1 Dashboard | Implémenté, peut être plus ancien que les fichiers séparés |
| `apex/components/customer-360/header.sql` | PL/SQL Dynamic Content de l’en-tête Customer 360 | Implémenté |
| `apex/components/customer-360/header.css` | Copie autonome des styles de l’en-tête | Implémenté |
| `apex/components/customer-360/README.md` | Instructions de configuration APEX de l’en-tête | Implémenté |
| `database/sed-dashboard/01_drop_objects.sql` | Suppression initiale d’objets | Partiel |
| `database/sed-dashboard/02_lookup_tables.sql` | Tables et données de lookup | Implémenté |
| `database/sed-dashboard/03_core_tables.sql` | Tables métier principales | Implémenté |
| `database/sed-dashboard/04_security_campaign_tables.sql` | Dossiers, événements et campagnes | Squelette `TODO` |
| `database/sed-dashboard/05_health_alert_tables.sql` | Historique Health et alertes | Squelette `TODO` |
| `database/sed-dashboard/06_constraints_indexes.sql` | Contraintes différées et index | Implémenté en partie ; vérifier les dépendances |
| `database/sed-dashboard/07_views_dashboard.sql` | Vue `v_apex_customer_portfolio` | Implémenté |
| `database/sed-dashboard/08_packages_spec.sql` | Spécifications des packages | Squelette `TODO` |
| `database/sed-dashboard/09_packages_body.sql` | Corps des packages | Squelette `TODO` |
| `database/sed-dashboard/10_minimal_apex_customers_contacts.sql` | Jeu de données minimal clients/contacts | Implémenté |
| `database/sed-dashboard/10_sample_data.sql` | Jeu de données MVP complet | Squelette `TODO` |
| `database/sed-dashboard/11_jobs.sql` | Jobs Scheduler | Squelette `TODO` |
| `database/sed-dashboard/12_validation_queries.sql` | Requêtes de validation | Squelette `TODO` |
| `database/sed-dashboard/13_security_publications.sql` | Table des publications de sécurité Oracle | Implémenté |

### 5.2 Documents de conception

- `docs/product/mvp.md` : périmètre fonctionnel complet du MVP.
- `design.txt` : vision produit générale.
- `Security_Advisor_Tasks.md` : tâches quotidiennes et hebdomadaires du persona.
- `docs/architecture/sql-implementation-plan.md` : plan détaillé du modèle SQL cible.
- `docs/operations/deployment-next-steps.md` : ordre historique de construction et déploiement.
- `docs/operations/minimal-apex-app.md` : guide de construction d’une première application APEX.
- `docs/architecture/ai-security-analysis.md` : architecture prévue pour l’analyse de sécurité assistée par IA.
- `apex/components/portfolio/legacy/` : ancienne variante de SQL/CSS du Portfolio ; préférer `apex/components/portfolio/report.sql` et `apex/static/dashboard.css` sauf besoin de comparaison.

## 6. Modèle de données réellement implémenté

### 6.1 Lookups

`database/sed-dashboard/02_lookup_tables.sql` crée les tables de référence suivantes :

- `customer_tiers`
- `customer_statuses`
- `team_roles`
- `health_statuses`
- `interaction_types`
- `review_statuses`
- `action_priorities`
- `action_statuses`
- `severity_levels`
- `security_case_types`
- `security_case_statuses`
- `security_impact_statuses`
- `security_impact_confidence_levels`
- `remediation_statuses`
- `security_event_types`
- `security_event_statuses`
- `notification_campaign_types`
- `notification_campaign_statuses`
- `notification_recipient_statuses`
- `alert_types`
- `alert_statuses`
- `estate_types`
- `estate_lifecycle_statuses`

Les tiers actuellement prévus sont :

- `TIER_1` : Tier 1 - Strategic
- `TIER_2` : Tier 2 - Enterprise
- `TIER_3` : Tier 3 - Growth
- `TIER_4` : Tier 4 - Digital

Les statuts Health principaux sont :

- `GOOD`
- `AT_RISK`
- `NEEDS_ATTENTION`

### 6.2 Utilisateurs internes

Table : `internal_users`

Champs principaux :

- identité : `user_id`, `full_name`, `email` ;
- fonction : `role_name`, `department` ;
- état : `active_flag` ;
- audit : `created_by`, `created_at`, `updated_by`, `updated_at`.

`email` est unique. `active_flag` accepte `Y` ou `N`.

### 6.3 Clients

Table : `customers`

Champs fonctionnels importants :

- `customer_id`
- `customer_name`
- `industry`
- `country`
- `region`
- `registryid`
- `arr`
- `tier_id`
- `status_id`
- `primary_security_advisor_user_id`
- `current_security_contact_id`
- `current_health_status_id`
- `current_health_score`
- `health_score_reason`
- `health_calculated_at`
- champs d’override manuel du Health
- notes, informations de source et audit.

Contraintes importantes :

- tier, statut et Security Advisor principal obligatoires ;
- score Health entre 0 et 100 ;
- drapeaux manuels en `Y/N` ;
- clés étrangères vers les lookups et `internal_users`.

Attention : `current_security_contact_id` existe dans la table, mais sa contrainte de clé étrangère doit être vérifiée dans `database/sed-dashboard/06_constraints_indexes.sql`, car `customer_contacts` est créé après `customers`.

### 6.4 Contacts

Table : `customer_contacts`

Elle stocke :

- nom et fonction ;
- type de rôle ;
- email et téléphone ;
- drapeaux contact principal et contact sécurité courant ;
- état actif.

Chaque contact appartient à un client.

### 6.5 Équipe de compte Oracle

Table : `oracle_account_team_members`

Relation entre :

- un client ;
- un utilisateur interne ;
- un rôle d’équipe.

Elle contient aussi les dates de début/fin et les drapeaux principal/actif.

### 6.6 Estate Oracle

Table : `customer_estate_items`

Elle inventorie les produits et services Oracle :

- type d’élément ;
- produit/service ;
- version ;
- mode de déploiement ;
- environnement ;
- région ;
- criticité métier ;
- pertinence sécurité ;
- statut de cycle de vie ;
- date de dernière vérification ;
- source et notes.

Cette table doit devenir une source importante de l’analyse d’exposition aux publications de sécurité.

### 6.7 Interactions

Table : `interactions`

Elle conserve :

- le client ;
- le type et la date ;
- le sujet et le résumé ;
- le propriétaire interne ;
- le contact externe ;
- les prochaines étapes ;
- les informations de source et d’audit.

La vue Portfolio utilise la date de la dernière interaction pour calculer `days_since_last_contact`.

### 6.8 Reviews

Table : `reviews`

Elle contient :

- type et date de review ;
- statut ;
- propriétaire ;
- agenda, notes et résultat ;
- date de complétion.

### 6.9 Actions

Table : `actions`

Elle contient :

- titre et description ;
- client ;
- propriétaire ;
- priorité et statut ;
- échéance ;
- résolution et complétion ;
- liens futurs vers `security_case_id` et `campaign_recipient_id`.

Attention : les tables référencées par ces deux derniers identifiants ne sont pas encore créées dans `database/sed-dashboard/04_security_campaign_tables.sql`. Les contraintes correspondantes sont donc différées.

### 6.10 Publications de sécurité

Table : `security_publications`

Elle stocke les publications officielles Oracle :

- origine et identifiant externe ;
- type `CPU`, `CSPU` ou `SECURITY_ALERT` ;
- titre, URL et date de publication ;
- état d’ingestion `CURRENT`, `NEW` ou `UPDATED` ;
- dates de première vue, dernière vue et dernier changement.

Une contrainte unique existe sur `(source_code, external_id)`.

Le mécanisme de collecte RSS n’est pas présent dans ce dépôt. Seule la table est implémentée.

## 7. Modèle cible non encore implémenté

Les objets suivants sont prévus mais absents ou uniquement mentionnés dans des fichiers `TODO` :

- `security_events`
- `security_cases`
- `security_case_events`
- `security_case_customer_impacts`
- `notification_campaigns`
- `notification_campaign_recipients`
- `relationship_health_snapshots`
- `alerts`
- package `pkg_health_score`
- package `pkg_security_case`
- package `pkg_notification_campaign`
- package `pkg_alert_generation`
- package `pkg_sample_data`
- jobs `JOB_SED_REFRESH_HEALTH`
- job `JOB_SED_HEALTH_SNAPSHOT`
- job `JOB_SED_GENERATE_ALERTS`

Le workflow cible est :

```text
publication ou événement de sécurité
    → dossier de sécurité
    → évaluation de l’impact par client
    → campagne de notification
    → destinataires de la campagne
    → actions de suivi
```

Ne pas créer de référence circulaire entre `actions` et les destinataires de campagne. Le plan MVP prévoit un lien à sens unique depuis `actions.campaign_recipient_id`.

## 8. Vue Portfolio

La vue `v_apex_customer_portfolio` est créée dans `database/sed-dashboard/07_views_dashboard.sql`.

Elle fournit :

- informations d’identité du client ;
- pays, région, secteur ;
- tier converti en `T1`, `T2`, etc. ;
- statut et libellé Health ;
- nombre de jours depuis le dernier contact ;
- prochaine action ouverte ;
- priorité et échéance de cette action ;
- liste agrégée des produits Oracle.

La vue utilise :

- un CTE pour la dernière interaction ;
- un classement `row_number()` des actions ouvertes ;
- une agrégation séparée des produits Estate ;
- des jointures séparées pour éviter la multiplication des lignes.

La requête d’affichage courante se trouve dans `apex/components/portfolio/report.sql`.

### 8.1 Navigation depuis le Portfolio

- Le nom du client mène à la page **5** avec `P5_CUSTOMER_ID`.
- Le bouton **Customer 360** mène à la page **21** avec `P21_CUSTOMER_ID`.
- Les actions mènent à la page **18** ou à l’alias `action`, selon le contexte.

Les URL sont générées avec `apex_page.get_url` puis échappées avec `apex_escape.html_attribute`.

## 9. Page 1 — Dashboard

Un export local existe dans `apex/exports/legacy/sed-dashboard-page-1.apx`.

Fonctions visibles ou préparées :

- carte de métrique du nombre total de clients ;
- répartition par tier ;
- rapport Portfolio ;
- styles de tier, Health, statut, actions et produits.

Le fichier exporté peut être plus ancien que :

- `apex/components/portfolio/report.sql`
- `apex/static/dashboard.css`

Pour une modification, utiliser les fichiers séparés comme référence actuelle, puis réexporter la page APEX après validation.

## 10. Page 21 — Customer 360

### 10.1 Paramètre principal

Item caché :

```text
P21_CUSTOMER_ID
```

Son stockage de session est configuré sur `request`. Toutes les régions Customer 360 filtrent leurs données avec cet identifiant.

La page utilise une protection `argumentsMustHaveChecksum`. Les liens doivent donc être produits avec les API APEX, comme c’est déjà le cas dans `apex/components/portfolio/report.sql`.

### 10.2 En-tête personnalisé

Le code se trouve dans `apex/components/customer-360/header.sql`.

Type APEX attendu :

- région **Dynamic Content** ;
- template **Standard** ;
- Static ID `customer360-header` ;
- région située en haut du conteneur Customer 360.

L’en-tête affiche :

- avatar avec les initiales calculées depuis le nom ;
- nom du client ;
- pays, région et secteur ;
- badge Tier ;
- badge indiquant si le Security Advisor principal est actif ;
- badge `Health n/100`.

Les couleurs Health sont dynamiques :

- `GOOD` : vert ;
- `AT_RISK` : orange ;
- `NEEDS_ATTENTION` : rouge ;
- absence de statut : gris.

Les valeurs issues de la base sont échappées avec `apex_escape.html`. Le code affiche « Client introuvable » si `P21_CUSTOMER_ID` ne correspond à aucun client.

### 10.3 Taille actuelle des textes

Après demande utilisateur, les tailles de police de l’en-tête ont été réduites de 50 % :

- initiales desktop : `15px` ;
- nom desktop : `18px` ;
- métadonnées desktop : `13px` ;
- badges desktop : `12px`.

Les dimensions de l’avatar, du conteneur et des badges n’ont pas été réduites. Si le résultat semble trop vide, réduire ensuite les hauteurs, paddings et espacements de manière proportionnelle, mais uniquement après validation visuelle.

### 10.4 Structure APEX observée

La définition fournie de la page 21 contient actuellement :

- région racine statique `Customer360` ;
- région Dynamic Content `Header` ;
- région `Customers` de type `themeTemplateComponent/contentRow` ;
- région `Customer Details` de type Tabs Container, enfant de `Customers` ;
- onglet `Overview` avec le texte `placeholder` ;
- onglet `Contacts`, Classic Report ;
- onglet `Estate`, Interactive Report ;
- bouton `Edit Customer`, redirigeant vers la page 5.

### 10.5 Région Content Row obsolète

La région `Customers` est un composant généré depuis un exemple Employee. Elle contient :

```text
overline: Employee
title: &NAME.
description: &JOB.
miscellaneous: &SALARY.
displayAvatar: true
displayBadge: true
badge value: CUSTOMER_ID
```

Conséquences observées :

- `<div class="t-ContentRow-overline">Employee</div>` provient de `overline: Employee`.
- `<span class="t-Badge-value">881</span>` provient du badge affichant `CUSTOMER_ID`; `881` est l’identifiant du client courant.
- `&NAME.`, `&JOB.` et `&SALARY.` sont des placeholders de démonstration qui ne correspondent pas aux colonnes de la requête.

Correction recommandée :

1. Déplacer `Customer Details` pour qu’il devienne directement une sous-région de `Customer360`.
2. Vérifier que les onglets Contacts, Estate et Overview restent enfants de `Customer Details`.
3. Supprimer la région Content Row `Customers`.
4. Conserver la région Dynamic Content `Header`.

Ne pas simplement masquer `Customers` avant de déplacer `Customer Details`, sinon les onglets enfants risquent également de disparaître.

### 10.6 Onglets existants

**Contacts**

Classic Report sur `customer_contacts`, filtré par `P21_CUSTOMER_ID`.

**Estate**

Interactive Report sur `customer_estate_items`, filtré par `P21_CUSTOMER_ID`.

**Overview**

Région encore vide, contenant seulement `placeholder`. Elle doit être remplacée par un résumé utile ou supprimée.

Les futurs onglets naturels sont :

- Overview ;
- Contacts ;
- Oracle Account Team ;
- Estate ;
- Interactions ;
- Reviews ;
- Actions ;
- Security Cases ;
- Health History ;
- Alerts.

## 11. CSS et conventions visuelles

Le fichier global est `apex/static/dashboard.css`.

### 11.1 Préfixes

Les classes applicatives utilisent le préfixe `sed-` :

- `sed-metric-*`
- `sed-portfolio-*`
- `sed-customer-*`
- `sed-tier-*`
- `sed-health-*`
- `sed-action-*`
- `sed-products`
- `sed-c360-*`
- `sed-security-event-*`

Continuer à utiliser ce préfixe pour éviter les collisions avec Universal Theme.

### 11.2 Universal Theme

Les classes `t-*` appartiennent à Oracle APEX Universal Theme. Ne pas modifier globalement une classe comme `.t-Region`, `.t-Badge-value` ou `.t-ContentRow-overline`.

Toujours limiter les overrides à un Static ID ou à une classe applicative :

```css
#customer360-header .t-Region-body { ... }
```

### 11.3 Chargement du CSS

La définition observée de la page 21 utilise :

```text
#APP_FILES#dashboard#MIN#.css
```

Vérifier dans Shared Components que les deux variantes nécessaires existent ou que la substitution `#MIN#` fonctionne avec les fichiers téléversés :

- `apex/static/dashboard.css`
- éventuellement `dashboard.min.css`

Si seule la version non minifiée existe, utiliser explicitement :

```text
#APP_FILES#dashboard.css
```

### 11.4 Duplication CSS Customer 360

Les styles Customer 360 existent à deux endroits :

- dans `apex/static/dashboard.css`, source globale recommandée ;
- dans `apex/components/customer-360/header.css`, copie autonome pour collage dans Page CSS Inline.

Lors d’une modification, maintenir les deux fichiers synchronisés ou supprimer la copie locale après confirmation que `apex/static/dashboard.css` est toujours chargé.

## 12. Sécurité de rendu APEX

Règles à conserver :

- échapper le texte de base de données avec `apex_escape.html` ;
- échapper les URL avec `apex_escape.html_attribute` ;
- générer les URL internes avec `apex_page.get_url` ;
- conserver la protection par checksum ;
- ne désactiver `Escape Special Characters` que pour une colonne contenant du HTML construit par le code et dont toutes les valeurs dynamiques ont déjà été échappées ;
- ne jamais afficher directement un texte utilisateur dans `htp.p` ;
- valider que `P21_CUSTOMER_ID` donne accès à un client autorisé pour l’utilisateur courant.

La dernière règle d’autorisation n’est pas encore implémentée localement. Le simple filtrage par identifiant n’est pas une politique d’accès suffisante.

## 13. Ordre d’installation SQL

Ordre historique prévu :

1. `database/sed-dashboard/01_drop_objects.sql`
2. `database/sed-dashboard/02_lookup_tables.sql`
3. `database/sed-dashboard/03_core_tables.sql`
4. `database/sed-dashboard/04_security_campaign_tables.sql`
5. `database/sed-dashboard/05_health_alert_tables.sql`
6. `database/sed-dashboard/06_constraints_indexes.sql`
7. `database/sed-dashboard/07_views_dashboard.sql`
8. `database/sed-dashboard/08_packages_spec.sql`
9. `database/sed-dashboard/09_packages_body.sql`
10. script de données ;
11. `database/sed-dashboard/11_jobs.sql`
12. `database/sed-dashboard/12_validation_queries.sql`
13. `database/sed-dashboard/13_security_publications.sql` selon le besoin.

Cet ordre n’est **pas exécutable comme installation complète aujourd’hui**, car les scripts 04, 05, 08, 09, 10, 11 et 12 contiennent encore des `TODO`.

Pour un environnement minimal déjà utilisé par APEX :

1. lookups ;
2. tables principales ;
3. contraintes/index compatibles ;
4. vue Portfolio ;
5. `database/sed-dashboard/10_minimal_apex_customers_contacts.sql`.

Toujours tester dans un schéma non productif. `01_drop_objects.sql` est potentiellement destructif et ne doit jamais être exécuté automatiquement sans inspection et accord explicite.

## 14. Données de démonstration

`database/sed-dashboard/10_minimal_apex_customers_contacts.sql` charge un ensemble de clients, contacts et Security Advisors pour la validation de l’application minimale.

Exemples présents :

- Acme Manufacturing ;
- Contoso Retail Group ;
- Northwind Health ;
- Fabrikam Energy ;
- Globex Financial Services ;
- Initech Cloud Services ;
- autres clients fictifs.

Les données sont de démonstration. Ne pas les confondre avec des comptes réels.

Le script complet `database/sed-dashboard/10_sample_data.sql` n’est pas implémenté.

## 15. Health Score

### 15.1 État actuel

Le modèle stocke :

- score actuel ;
- statut actuel ;
- raison ;
- date de calcul ;
- override manuel et justification.

Le calcul automatique et l’historique ne sont pas encore codés. La règle
confirmée pour la future implémentation centralisée est la suivante : la
présence d’au moins un produit Estate dont `ORACLE_ACRONYMS.SECALERT` vaut
`TRUE` ajoute 30 points, une seule fois par client. Le score est un score de
risque croissant, plafonné à 100, et un score supérieur ou égal à 30 doit
produire le statut `NEEDS_ATTENTION`. Les régions APEX ne calculent pas cette
contribution ; elles lisent uniquement le score et le statut persistés.

### 15.2 Cible

Le score doit rester simple et explicable. Les signaux envisagés comprennent :

- ancienneté du dernier contact ;
- actions en retard ;
- reviews à venir ou manquées ;
- alertes ouvertes ;
- criticité des dossiers de sécurité ;
- avancement des campagnes ;
- qualité ou fraîcheur des données Estate ;
- tier du client.

Seuils et pondérations doivent être centralisés dans `pkg_health_score`, documentés et testables.

## 16. Analyse de sécurité assistée par IA

Le plan se trouve dans `docs/architecture/ai-security-analysis.md`.

### 16.1 Objectif

Corréler :

- Estate Oracle du client ;
- contexte Health, actions et dossiers ;
- publications de sécurité Oracle fiables ;
- informations manquantes ;
- recommandations de suivi.

### 16.2 Sortie attendue

La sortie doit être structurée, par exemple :

- résumé ;
- niveau de confiance ;
- exposition potentielle ;
- produits ou versions concernés ;
- preuves utilisées ;
- informations manquantes ;
- actions recommandées ;
- avertissements ;
- statut de revue humaine.

### 16.3 Garde-fous

- Ne jamais présenter une exposition comme certaine sans preuve suffisante.
- Conserver les URLs et identifiants de publication.
- Distinguer fait, hypothèse et information manquante.
- Ne pas modifier automatiquement le Health.
- Ne pas créer automatiquement d’action ou envoyer une communication sans confirmation humaine.
- Ne pas envoyer au modèle plus de données client que nécessaire.

Cette fonctionnalité est planifiée, pas implémentée.

## 17. Problèmes connus et points à vérifier

1. **Région Content Row obsolète sur la page 21**
   - Produit `Employee` et le badge de `CUSTOMER_ID`.
   - À supprimer après déplacement du Tabs Container.

2. **Overview vide**
   - Contient seulement `placeholder`.

3. **Scripts SQL incomplets**
   - Plusieurs fichiers importants ne contiennent que des commentaires `TODO`.

4. **Export APEX incomplet**
   - Seule la page 1 est stockée localement.
   - La page 21 a été fournie comme texte, mais n’est pas encore enregistrée comme export versionné dans le projet.

5. **Écart possible entre local et APEX**
   - Les fichiers CSS/SQL locaux peuvent différer de ce qui est chargé dans l’application.

6. **CSS `#MIN#`**
   - Vérifier la présence de la variante minifiée.

7. **Polices Customer 360**
   - Réduites de 50 %, mais les dimensions des composants sont restées grandes.

8. **Autorisations**
   - Aucun contrôle complet « Security Advisor ne voit que ses clients » n’est confirmé dans le code local.

9. **Packages et jobs**
   - Aucun calcul automatique Health ou génération d’alertes n’est disponible.

10. **Collecte RSS**
    - La table existe, mais le processus d’ingestion n’est pas présent.

11. **Tests**
    - Pas de suite automatisée.
    - `database/sed-dashboard/12_validation_queries.sql` est encore un squelette.

## 18. Prochaines étapes recommandées

### Priorité 1 — Nettoyer et stabiliser Customer 360

1. Déplacer `Customer Details` sous la région racine `Customer360`.
2. Supprimer la région Content Row `Customers`.
3. Remplacer le placeholder Overview.
4. Vérifier le rendu desktop et mobile de l’en-tête.
5. Réexporter la page 21 et enregistrer l’export dans `apex/exports/`.

### Priorité 2 — Versionner l’état APEX réel

1. Exporter l’application ou au minimum les pages 1 et 21.
2. Exporter les Shared Components utiles.
3. Enregistrer la configuration des Static Application Files.
4. Comparer l’export avec `apex/static/dashboard.css` et les SQL locaux.

### Priorité 3 — Compléter le socle SQL

1. Implémenter `04_security_campaign_tables.sql`.
2. Implémenter `05_health_alert_tables.sql`.
3. Adapter `06_constraints_indexes.sql`.
4. Compléter le script de suppression de façon sûre.
5. Écrire des validations réexécutables.

### Priorité 4 — Logique métier

1. Implémenter et tester `pkg_health_score`.
2. Implémenter les packages sécurité et campagnes.
3. Charger des données de test cohérentes.
4. Créer les jobs désactivés par défaut.

### Priorité 5 — Sécurité et autorisations

1. Définir les rôles APEX.
2. Définir qui peut voir tous les clients ou uniquement son portefeuille.
3. Ajouter des Authorization Schemes.
4. Vérifier chaque rapport et chaque processus DML.

### Priorité 6 — IA

Commencer uniquement après stabilisation du modèle de données, des publications et du workflow de revue humaine.

## 19. Contrôles avant toute nouvelle modification

Une IA qui reprend le projet doit suivre cette séquence :

1. Lire ce document.
2. Lire le fichier directement concerné par la demande.
3. Vérifier si un export APEX plus récent existe.
4. Distinguer le code local de l’état déployé.
5. Rechercher les références avec `rg` avant de renommer un item, une page ou une classe.
6. Préserver `P21_CUSTOMER_ID` et les liens avec checksum.
7. Ne pas modifier les scripts destructifs sans accord.
8. Échapper toutes les valeurs dynamiques injectées dans du HTML.
9. Garder `apex/static/dashboard.css` et `apex/components/customer-360/header.css` synchronisés.
10. Fournir à l’utilisateur des étapes APEX précises lorsque la modification ne peut pas être appliquée uniquement dans le dépôt.

## 20. Scénarios minimaux de validation

### 20.1 Portfolio

- La page 1 affiche les clients.
- Le tier et le Health ont la bonne couleur.
- Le dernier contact est calculé correctement.
- Les actions ouvertes sont affichées.
- Le bouton Customer 360 ouvre la page 21 avec le bon client.

### 20.2 Customer 360

- `P21_CUSTOMER_ID` est alimenté.
- L’en-tête affiche le bon nom et les bonnes initiales.
- Pays, région et secteur sont corrects.
- Tier, état du Security Advisor et Health sont corrects.
- Aucun texte `Employee`, `&NAME.`, `&JOB.` ou `&SALARY.` n’apparaît.
- Aucun badge contenant uniquement le `CUSTOMER_ID` n’apparaît.
- Contacts et Estate ne montrent que les lignes du client courant.
- Le bouton Edit Customer ouvre la page 5 avec `P5_CUSTOMER_ID`.

### 20.3 Sécurité

- Une URL sans checksum valide est refusée selon la politique APEX.
- Un utilisateur non autorisé ne peut pas accéder à un autre client en changeant l’identifiant.
- Les valeurs contenant `<`, `>`, `&`, guillemets ou apostrophes sont rendues sans injection HTML.

### 20.4 Responsive

- L’en-tête reste lisible sur mobile.
- Les badges passent à la ligne sans déborder.
- Les rapports restent utilisables sur un écran étroit.

## 21. Définition de “terminé” pour une prochaine tâche

Une tâche n’est considérée terminée que si :

- le code local est modifié dans le bon fichier ;
- la configuration APEX nécessaire est explicitement décrite ou exportée ;
- les doublons concernés sont synchronisés ;
- les dépendances SQL sont respectées ;
- les valeurs dynamiques sont échappées ;
- une vérification proportionnée au risque a été réalisée ;
- les limites de validation locale sont clairement signalées.

## 22. Résumé opérationnel pour la prochaine IA

Le projet dispose d’un bon modèle fonctionnel et d’un socle Oracle/APEX partiellement construit. Le Dashboard, le Portfolio, les tables principales, les lookups, la vue Portfolio, les données minimales, la table des publications et l’en-tête Customer 360 ont du code concret.

Le principal travail immédiat est de stabiliser la page 21, supprimer son ancien composant Content Row, versionner l’export APEX réel, puis compléter les scripts SQL encore vides. Les campagnes, dossiers de sécurité, historique Health, alertes, packages, jobs et intégration IA sont des cibles, pas des fonctionnalités déjà disponibles.

Toujours commencer par vérifier l’état réel dans APEX et Oracle avant de modifier le dépôt local.
