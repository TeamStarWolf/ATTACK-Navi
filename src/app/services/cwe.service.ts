// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, catchError, of } from 'rxjs';

export interface CweInfo {
  id: string;
  name: string;
  description: string;
  url: string;
}

interface CweEntry {
  name: string;
  description: string;
}

@Injectable({ providedIn: 'root' })
export class CweService {
  private catalog = new Map<string, CweEntry>();
  private loadedSubject = new BehaviorSubject<boolean>(false);
  readonly loaded$ = this.loadedSubject.asObservable();

  constructor(private http: HttpClient) {
    // Seed with static MAP
    for (const [k, v] of Object.entries(CweService.MAP)) {
      this.catalog.set(k, v);
    }
    // Fetch full catalog
    this.http.get<Record<string, CweEntry>>('assets/data/cwe-catalog.json')
      .pipe(catchError(() => of(null)))
      .subscribe(data => {
        if (data) {
          for (const [k, v] of Object.entries(data)) {
            this.catalog.set(k, v);
          }
        }
        this.loadedSubject.next(true);
      });
  }

  private static readonly MAP: Record<string, CweEntry> = {
    '20':   { name: 'Improper Input Validation',            description: 'The product receives input that it does not validate properly, allowing attackers to craft inputs that violate assumptions.' },
    '22':   { name: 'Path Traversal',                       description: 'The software uses external input to construct a pathname that should be restricted but allows traversal outside the intended directory.' },
    '74':   { name: 'Injection',                            description: 'The software constructs all or part of a command, data structure, or record using externally-influenced input, but does not neutralize special elements.' },
    '77':   { name: 'Command Injection',                    description: 'The software constructs a command using externally-influenced input but does not neutralize special elements that could modify the intended command.' },
    '78':   { name: 'OS Command Injection',                 description: 'The software constructs an OS command using externally-influenced input but does not neutralize elements that can modify the intended command.' },
    '79':   { name: 'Cross-site Scripting (XSS)',           description: 'The software does not neutralize user-controllable input before it is placed in output that is used as a web page served to other users.' },
    '89':   { name: 'SQL Injection',                        description: 'The software constructs all or part of an SQL query using externally-influenced input, allowing attackers to modify the query logic.' },
    '94':   { name: 'Code Injection',                       description: 'The software constructs all or part of a code segment using externally-influenced input, which can be executed by the application.' },
    '119':  { name: 'Buffer Overflow',                      description: 'The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside the intended boundary.' },
    '120':  { name: 'Classic Buffer Overflow',              description: 'The software copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.' },
    '121':  { name: 'Stack-based Buffer Overflow',          description: 'A buffer overflow condition in which the buffer that can be overwritten is allocated on the stack.' },
    '122':  { name: 'Heap-based Buffer Overflow',           description: 'A buffer overflow condition in which the buffer that can be overwritten is allocated on the heap.' },
    '125':  { name: 'Out-of-bounds Read',                   description: 'The software reads data past the end, or before the beginning, of the intended buffer.' },
    '134':  { name: 'Uncontrolled Format String',           description: 'The software uses externally-controlled input to construct a format string used in a printf-style function, allowing attackers to read memory or execute code.' },
    '190':  { name: 'Integer Overflow',                     description: 'The software performs a calculation that can produce an integer overflow, causing the result to wrap around to a different value.' },
    '191':  { name: 'Integer Underflow',                    description: 'The software performs a calculation that can produce an integer underflow, causing the result to wrap to an unexpectedly large value.' },
    '200':  { name: 'Information Exposure',                 description: 'The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.' },
    '209':  { name: 'Error Message Information Exposure',   description: 'The software generates an error message that includes sensitive information about its environment, users, or associated data.' },
    '269':  { name: 'Improper Privilege Management',        description: 'The software does not properly assign, modify, track, or check privileges, creating an unintended sphere of control for that actor.' },
    '276':  { name: 'Incorrect Default Permissions',        description: 'During installation, installed file permissions are set to allow anyone to modify those files.' },
    '284':  { name: 'Improper Access Control',              description: 'The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.' },
    '285':  { name: 'Improper Authorization',               description: 'The software does not perform or incorrectly performs an authorization check when an actor attempts to access a resource or perform an action.' },
    '287':  { name: 'Improper Authentication',              description: 'The software does not correctly implement authentication, allowing access to functionality and data that should be restricted.' },
    '295':  { name: 'Improper Certificate Validation',      description: 'The software does not validate, or incorrectly validates, a certificate, allowing attackers to spoof trusted identities.' },
    '306':  { name: 'Missing Authentication for Critical Function', description: 'The software does not perform any authentication for functionality that requires a provably unique or traceable identity.' },
    '307':  { name: 'Improper Restriction of Excessive Authentication Attempts', description: 'The software does not implement sufficient measures to prevent multiple failed authentication attempts, enabling brute-force attacks.' },
    '310':  { name: 'Cryptographic Issues',                 description: 'Weaknesses in this category are related to the design and implementation of data confidentiality and integrity.' },
    '311':  { name: 'Missing Encryption of Sensitive Data', description: 'The software does not encrypt sensitive or critical information before storage or transmission.' },
    '312':  { name: 'Cleartext Storage of Sensitive Information', description: 'The application stores sensitive information in cleartext within a resource that might be accessible to another control sphere.' },
    '319':  { name: 'Cleartext Transmission of Sensitive Information', description: 'The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed.' },
    '320':  { name: 'Key Management Errors',                description: 'Weaknesses in this category are related to errors in the management of cryptographic keys.' },
    '326':  { name: 'Inadequate Encryption Strength',       description: 'The software stores or transmits sensitive data using an encryption scheme that is theoretically sound, but not strong enough for the level of risk.' },
    '327':  { name: 'Use of a Broken or Risky Cryptographic Algorithm', description: 'The use of a broken or risky cryptographic algorithm is an unnecessary risk that may result in the exposure of sensitive information.' },
    '328':  { name: 'Reversible One-Way Hash',              description: 'The product uses a hashing algorithm that produces a hash value that can be reversed or cracked more easily than expected.' },
    '330':  { name: 'Use of Insufficiently Random Values',  description: 'The software uses insufficiently random numbers or values in a security context that depends on unpredictable numbers.' },
    '338':  { name: 'Use of Cryptographically Weak PRNG',   description: 'The product uses a Pseudo-Random Number Generator (PRNG) in a security context, but the PRNG\'s algorithm is not cryptographically strong.' },
    '345':  { name: 'Insufficient Verification of Data Authenticity', description: 'The software does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.' },
    '346':  { name: 'Origin Validation Error',              description: 'The software does not properly verify that the source of data or communication is valid.' },
    '347':  { name: 'Improper Verification of Cryptographic Signature', description: 'The software does not verify, or incorrectly verifies, the cryptographic signature for data.' },
    '352':  { name: 'Cross-Site Request Forgery (CSRF)',    description: 'The web application does not, or can not, sufficiently verify whether a well-formed, valid, consistent request was intentionally provided by the user.' },
    '362':  { name: 'Race Condition',                       description: 'The program contains a code sequence that can run concurrently with other code, and the code sequence requires temporary, exclusive access to a shared resource.' },
    '369':  { name: 'Divide By Zero',                       description: 'The product divides a value by zero.' },
    '377':  { name: 'Insecure Temporary File',              description: 'Creating and using insecure temporary files can leave application and system data vulnerable to attack.' },
    '384':  { name: 'Session Fixation',                     description: 'Authenticating a user, or otherwise establishing a new user session, without invalidating any existing session identifier.' },
    '400':  { name: 'Uncontrolled Resource Consumption',    description: 'The software does not properly control the allocation and maintenance of a limited resource, allowing a DoS condition.' },
    '401':  { name: 'Memory Leak',                          description: 'The software does not sufficiently track and release allocated memory after it has been used, causing memory exhaustion.' },
    '404':  { name: 'Improper Resource Shutdown or Release', description: 'The program does not release or incorrectly releases a resource before it is made available for re-use.' },
    '416':  { name: 'Use After Free',                       description: 'Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code.' },
    '426':  { name: 'Untrusted Search Path',                description: 'The application searches for critical resources using an externally-supplied search path that can point to resources that are not under the application\'s direct control.' },
    '427':  { name: 'Uncontrolled Search Path Element',     description: 'The product uses a fixed or controllable search path to find resources, but one or more locations in that path can be under the control of unintended actors.' },
    '434':  { name: 'Unrestricted Upload of File with Dangerous Type', description: 'The software allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product\'s environment.' },
    '436':  { name: 'Interpretation Conflict',              description: 'Product A handles inputs or steps differently than Product B, which causes A to perform incorrect actions based on its perception of B\'s state.' },
    '444':  { name: 'HTTP Request Smuggling',               description: 'When malformed or abnormal HTTP requests are interpreted differently by front-end and back-end HTTP servers, an attacker can poison the request queue.' },
    '476':  { name: 'NULL Pointer Dereference',             description: 'A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, causing a crash or unexpected behavior.' },
    '502':  { name: 'Deserialization of Untrusted Data',    description: 'The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid.' },
    '522':  { name: 'Insufficiently Protected Credentials', description: 'This weakness occurs when the software transmits or stores authentication credentials, but uses an insecure method that is susceptible to unauthorized interception or retrieval.' },
    '532':  { name: 'Insertion of Sensitive Information into Log File', description: 'Information written to log files can be of a sensitive nature and give valuable guidance to an attacker or expose user data.' },
    '538':  { name: 'File and Directory Information Exposure', description: 'The product makes sensitive information about a file or directory accessible to actors who are not authorized to access it.' },
    '539':  { name: 'Use of Persistent Cookies Containing Sensitive Information', description: 'The web application uses persistent cookies, but the cookies contain sensitive information.' },
    '552':  { name: 'Files or Directories Accessible to External Parties', description: 'The product makes files or directories accessible to unauthorized actors, even though they should not be.' },
    '601':  { name: 'URL Redirection to Untrusted Site (Open Redirect)', description: 'A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect.' },
    '611':  { name: 'Improper Restriction of XML External Entity Reference (XXE)', description: 'The software processes an XML document that can contain XML entities with URIs that resolve to documents outside of the intended sphere of control.' },
    '613':  { name: 'Insufficient Session Expiration',      description: 'According to OWASP, Insufficient Session Expiration is when a web site permits an attacker to reuse old session credentials or session IDs for authorization.' },
    '620':  { name: 'Unverified Password Change',           description: 'The software does not require knowledge of the existing password in order to change it, which could allow attackers to change another user\'s password.' },
    '639':  { name: 'Authorization Bypass Through User-Controlled Key (IDOR)', description: 'The system\'s authorization functionality does not prevent one user from gaining access to another user\'s data by modifying the key value identifying the data.' },
    '640':  { name: 'Weak Password Recovery Mechanism',     description: 'The software contains a mechanism for users to recover or change their passwords without knowing the original password, but the mechanism is weak.' },
    '693':  { name: 'Protection Mechanism Failure',         description: 'The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.' },
    '703':  { name: 'Improper Check or Handling of Exceptional Conditions', description: 'The software does not properly handle unexpected errors or exceptional conditions.' },
    '704':  { name: 'Incorrect Type Conversion or Cast',    description: 'The software does not correctly convert an object, resource, or structure from one type to a different type.' },
    '732':  { name: 'Incorrect Permission Assignment for Critical Resource', description: 'The software specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.' },
    '754':  { name: 'Improper Check for Unusual or Exceptional Conditions', description: 'The software does not check or incorrectly checks for unusual or exceptional conditions that are not expected to occur frequently during normal operation.' },
    '755':  { name: 'Improper Handling of Exceptional Conditions', description: 'The software does not handle or incorrectly handles an exceptional condition.' },
    '770':  { name: 'Allocation of Resources Without Limits or Throttling', description: 'The software allocates a reusable resource or group of resources on behalf of an actor without imposing any restrictions on the size or number of resources that can be allocated.' },
    '787':  { name: 'Out-of-bounds Write',                  description: 'The software writes data past the end, or before the beginning, of the intended buffer.' },
    '798':  { name: 'Use of Hard-coded Credentials',        description: 'The software contains hard-coded credentials, such as a password or cryptographic key, which it uses for its own inbound authentication, outbound communication, or encryption of internal data.' },
    '807':  { name: 'Reliance on Untrusted Inputs in a Security Decision', description: 'The application uses a protection mechanism that relies on the existence or values of an input, but the input can be modified by an untrusted actor.' },
    '824':  { name: 'Access of Uninitialized Pointer',      description: 'The program accesses or uses a pointer that has not been initialized, leading to undefined or unexpected behavior.' },
    '843':  { name: 'Access of Resource Using Incompatible Type (Type Confusion)', description: 'The program allocates or initializes a resource such as a pointer, object, or variable using one type, but it later accesses that resource using a type that is incompatible with the original type.' },
    '862':  { name: 'Missing Authorization',                description: 'The software does not perform an authorization check when an actor attempts to access a resource or perform an action.' },
    '863':  { name: 'Incorrect Authorization',              description: 'The software performs an authorization check, but the check is incorrectly implemented, allowing unauthorized actors to access restricted resources.' },
    '918':  { name: 'Server-Side Request Forgery (SSRF)',   description: 'The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.' },
    '922':  { name: 'Insecure Storage of Sensitive Information', description: 'The application stores sensitive information without properly restricting read or write access to it.' },
    '942':  { name: 'Permissive Cross-domain Policy with Untrusted Domains', description: 'The software uses a cross-domain policy file that includes domains that should not be trusted.' },
    '1021': { name: 'Improper Restriction of Rendered UI Layers (Clickjacking)', description: 'The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain, causing the user to unknowingly perform actions in another context.' },
    '1236': { name: 'Improper Neutralization of Formula Elements in a CSV File (CSV Injection)', description: 'The software saves user-provided information into a Comma-Separated Value (CSV) file, but it does not neutralize formula-starting characters.' },
  };

  /** Normalize a CWE id string to just the numeric part, e.g. "CWE-78" or "78" → "78" */
  private normalize(cweId: string): string {
    return cweId.replace(/^CWE-/i, '').trim();
  }

  getUrl(cweId: string): string {
    const num = this.normalize(cweId);
    return `https://cwe.mitre.org/data/definitions/${num}.html`;
  }

  getInfo(cweId: string): CweInfo | null {
    const num = this.normalize(cweId);
    const entry = this.catalog.get(num) ?? CweService.MAP[num];
    if (!entry) return null;
    return {
      id: `CWE-${num}`,
      name: entry.name,
      description: entry.description,
      url: this.getUrl(cweId),
    };
  }
}
