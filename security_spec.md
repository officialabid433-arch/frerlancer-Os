# Security Specification: Freelancer OS Security Model

## 1. Core Data Invariants
1. **User Profiling Sandboxing**: A user is strictly blocked from reading or writing a profile document in `users` with an ID different from their own authenticated `uid`.
2. **Strict Document ownership**: Clients, Projects, Invoices, Payments, and Activities must have an immutable `userId` that strictly matches the authenticated user: `request.auth.uid`.
3. **No Cross-Tenant Read/Write**: Query isolation must always prevent an authenticated user `A` from reading, updating, or deleting components owned by user `B`.
4. **Relational Referencing Consistency**:
   - Creating a project requires that the assigned `clientId` exists and belongs to the user.
   - Creating an invoice or payment requires that the target `clientId` or `invoiceId` exists and belongs to the user.
5. **No System Key Injection**: Validation helpers must refuse shadow properties or unexpected keys beyond those explicitly documented.
6. **Immutable Fields Protection**: Critical fields such as `createdAt` and `userId` must be locked and remain unchangeable during document updates.
7. **Strict Field Validation Size Enforcements**: All string properties must have a documented length limit, e.g. text/notes length bounds, to prevent memory or buffer issues.
8. **Temporal Integrity**: All write operations must bind timestamp checks, specifically tracking created and updated values directly to `request.time`.

---

## 2. The "Dirty Dozen" Malicious Payloads
Here are the 12 malicious payloads designed to subvert user boundaries:

### #1: User Profile Theft (Identity Hijacking)
*   **Path**: `/users/attacker_user_id` (by an authenticated User `victim_user_id`)
*   **Payload**:
    ```json
    {
      "userId": "attacker_user_id",
      "name": "Attacker Name",
      "email": "attacker@hacker.io",
      "createdAt": "2026-06-06T12:00:00Z"
    }
    ```
*   **Vector**: Attempting to write into another user's profile resource using a spoofed UID path.

### #2: Unauthorized Client Interception (Cross-Tenant Writing)
*   **Path**: `/clients/victim_client_id` (by attacker `attacker_uid`)
*   **Payload**:
    ```json
    {
      "id": "victim_client_id",
      "userId": "victim_uid",
      "clientName": "Victim's Client",
      "email": "admin@victim.com",
      "status": "Active",
      "createdAt": "2026-06-06T12:00:00Z"
    }
    ```
*   **Vector**: Attempt to overwrite or create a client record belonging to a different user, bypassing authentication matching.

### #3: System RBAC Injection (Shadow Fields Attack)
*   **Path**: `/users/attacker_uid`
*   **Payload**:
    ```json
    {
      "userId": "attacker_uid",
      "name": "Attacker",
      "email": "attacker@gmail.com",
      "companyName": "Hackers Ltd",
      "freelancerCategory": "Engineering",
      "country": "US",
      "createdAt": "2026-06-06T12:00:00Z",
      "isAdmin": true
    }
    ```
*   **Vector**: Injecting an unrequested boolean field `isAdmin: true` inside a standard profile payload to gain access to system privileges.

### #4: Rogue Client Status Shortcuts
*   **Path**: `/clients/client_id` (on Update)
*   **Payload**:
    ```json
    {
      "status": "MALICIOUS_STATUS"
    }
    ```
*   **Vector**: Attempting to bypass the allowed status enum value (`Active`, `Inactive`, `Lead`) with an arbitrary string.

### #5: Project Deadline Poisoning (Unbounded Data Attacks)
*   **Path**: `/projects/project_id` (on Create)
*   **Payload**:
    ```json
    {
      "id": "project_id",
      "userId": "attacker_uid",
      "clientId": "client_id",
      "projectName": "Big Project",
      "budget": 5000,
      "deadline": "<script>alert('compromised')</script>................................[repeated to 5MB]",
      "status": "Pending",
      "createdAt": "2026-06-06T12:00:00Z"
    }
    ```
*   **Vector**: Injecting HTML scripts or immensely long strings directly into the script fields to exhaust billing database memory.

### #6: Orphaned Project Association (No Relational Truth)
*   **Path**: `/projects/project_id`
*   **Payload**:
    ```json
    {
      "id": "project_id",
      "userId": "attacker_uid",
      "clientId": "non_existent_client_id_0000000000000",
      "projectName": "Orphan Project",
      "budget": 1000,
      "status": "Pending",
      "createdAt": "2026-06-06T12:00:00Z"
    }
    ```
*   **Vector**: Creating a project that references an invalid, non-existent `clientId` to disrupt collection referential integrity.

### #7: Invoice Auto-Increment Hijacking (Invoice Spoofing)
*   **Path**: `/invoices/invoice_id`
*   **Payload**:
    ```json
    {
      "id": "invoice_id",
      "invoiceNumber": "INV-888888888888888888888888888888888888888",
      "userId": "victim_uid",
      "clientId": "victim_client_id",
      "clientName": "Victim client",
      "invoiceDate": "2026-06-06",
      "dueDate": "2026-07-06",
      "items": [],
      "totalAmount": 99999999,
      "status": "Paid",
      "createdAt": "2026-06-06T12:00:00Z"
    }
    ```
*   **Vector**: Injecting extreme billing values and overwriting serial numbers on invoices to perform denial-of-wallet or credit injection.

### #8: Overdue Invoice Forgery (State Shortcutting)
*   **Path**: `/invoices/invoice_id`
*   **Payload**:
    ```json
    {
      "status": "Paid"
    }
    ```
*   **Vector**: Modifying the invoice payment status directly to "Paid" via client scripts without processing actual billing ledgers or matching transactions.

### #9: Negative Ledger Value Tampering (Resource Exhaustion)
*   **Path**: `/payments/pay_id`
*   **Payload**:
    ```json
    {
      "id": "pay_id",
      "userId": "attacker_uid",
      "invoiceId": "invoice_id",
      "invoiceNumber": "INV-100",
      "amount": -50000,
      "paymentDate": "2026-06-06",
      "paymentStatus": "Paid",
      "createdAt": "2026-06-06T12:00:00Z"
    }
    ```
*   **Vector**: Recording negative payment figures to reduce calculated total gross revenue or hijack financial summaries.

### #10: Auditing Trail Disruption (Log Spoofing)
*   **Path**: `/activities/activity_id_1`
*   **Payload**:
    ```json
    {
      "id": "activity_id_1",
      "userId": "victim_uid",
      "description": "User profile logged out",
      "type": "auth",
      "createdAt": "2026-06-06T12:00:00Z"
    }
    ```
*   **Vector**: Creating spoofed activity events pretending to act on behalf of a victim user to mask unauthorized network activities.

### #11: Immutable Registration Backdating
*   **Path**: `/clients/client_id` (on Update)
*   **Payload**:
    ```json
    {
      "createdAt": "2010-01-01T00:00:00Z"
    }
    ```
*   **Vector**: Updating a client entry to alter historical record timestamp lines.

### #12: Client-Side Query Sweep (Harvesting Data Vectors)
*   **Operation**: Listing all database profiles in `clients` or `invoices` without filtering `userId`.
*   **Vector**: Issuing an unrestricted `.get()` or `allow list` query to scrape records belonging to other users.

---

## 3. Test Runner Design Constraints
Our Security Rules must be implemented in a file named `firestore.rules`.
Each validation helper begins with structural constraints, verifying `userId` match and property bounds.
All of the malicious vectors above will result in `PERMISSION_DENIED` errors.
