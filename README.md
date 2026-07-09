# API Layer Documentation

## Overview

All API calls in client are centralised in `/src/api/`. **Do not use `fetch` or `apiFetch` anymore**, they should always go through the service classes.

```
useApi (hook)
  |-> ApiClient (pub)     (no auth token)
  |-> ApiClient (priv)    (attaches Auth0 JWT on every request)
  |----> Services
        |-> ClinicService       (done)
        |-> UserService         (done)
        |-> ScheduleService     (done)
        |-> AppointmentService  (done)
        |-> QueueService        (done)
        |-> SpecialityService   (done)
        |-> ConsultService      (done)
```

---

## File Structure

```
src/
|-- api/
    |-- ApiClient.js          
    |-- ResourceService.js    
    |-- useApi.js             
    |-- services/
        |-- ClinicService.js      
        |-- UserService.js        
        |-- ScheduleService.js
        |-- AppointmentService.js
        |-- QueueService.js
        |-- SpecialityService.js
        |-- ConsultService.js
```

---

## Core Classes

### `ApiClient` (not used in components, just info on how it works)

Handles all API communication. Never use this directly, it is used internally by the services.

**Constructor**
```js
new ApiClient(baseUrl, getToken = null)
```
- `baseUrl` - the base URL for all requests.
- `getToken` - optional Auth0 JWT token fetching function. `null` is used for public calls (those without required token).

**Methods**
```js
client.get(path, params)
client.post(path, body, params)
client.put(path, body, params)
client.patch(path, body, params)
client.delete(path, body, params)
```
- `params` - object converted to URL string: (`?key=value`).
- `body` - object that gets serialised as JSON request body.
- Throws `ApiError` if the response is not ok.

---

### `ResourceService` (not used in components, just info on how it works)

Base class for all services. Each service defines it's own methods.

```js
export class ResourceService {
  constructor(publicClient, privateClient, basePath) {
    this.pub = publicClient;    // public (no token)
    this.priv = privateClient;  // private (token)
    this.basePath = basePath;   // e.g. "/clinics"
  }
}
```

---

### `useApi` - used in components!

Builds and returns all service instances, called once in component (page).

```js
// in a page
import { useApi } from '../api/useApi';

const api = useApi();
```

Returns:
```js
{
  clinics,       // ClinicService
  users,         // UserService
  schedules,     // ScheduleService
  appointments,  // AppointmentService
  queues,        // QueueService
  specialities,  // SpecialityService
  consults,      // ConsultService
}
```

**Important:** `useApi` uses `useMemo` - the instances are cached across renders as long as the Auth0 token function doesn't change. Only call `useApi` at the top of a component, not in loops or conditional statements.

---

## Existing Services

### `UserService`

Base path: `/users`. All routes are private.

| Method | Server route |
|---|---|
| `register({ auth0Id, name, surname, title, email, role })`| `POST /api/users/register` |
| `get(auth0Id)`| `GET /api/users/:auth0Id` |
| `update(auth0Id, updates)`| `PATCH /api/users/:auth0Id` |

**Example usage in a component**
```js
const api = useApi();

// Register (pass all fields - server requries them)
await api.users.register({
  auth0Id: 'auth0|abc123',
  name: 'Jane',
  surname: 'Doe',
  title: 'Dr',
  email: 'jane@example.com',
  role: 'Admin',
});

// Get
const user = await api.users.get('auth0|abc123');

// Update (pass only changed fields)
await api.users.update('auth0|abc123', { email: 'new@example.com' });
```

---

### `ClinicService`

Base path: `/clinics`

Some routes are public (no token), some are private (token required) — this is handled internally per method.

| Method | Auth | Description | Server route |
|---|---|---|---|
| `filterAll(queryParams)` | Public | Get all clinics with optional filters | `GET /clinics/` |
| `getFilters(queryParams)` | Public | Get available filter options | `GET /clinics/filters/` |
| `getById(clinicId)` | Public | Get a single clinic | `GET /clinics/:clinicId` |
| `getAssignedClinics(auth0Id)` | Private | Get list of clinics assigned to a staff member | `GET /api/clinics/assigned/` |
| `linkAdmin(auth0Id, clinicId, practiceNumber)` | Private | Link an admin to a clinic (currently createClinic in server) | `POST /api/clinics/` |
| `updateClinic(clinicId, updates)` | Private | Update clinic fields | `PUT /api/clinics/:clinicId` |
| `listStaff(clinicId)` | Private | List all staff for a clinic | `GET /api/clinics/:clinicId/staff` |
| `linkStaff(clinicId, { auth0Id, id, email })` | Private | Link a staff member to a clinic | `POST /api/clinics/:clinicId/staff` |
| `removeStaff(clinicId, staffId)` | Private | Remove a staff member from a clinic | `DELETE /api/clinics/:clinicId/staff/:staffId` |

**Examples**
```js
const api = useApi();

// Public - no login required
const clinics = await api.clinics.filterAll({ province: 'gauteng', service: 'Maternity' });
const clinic = await api.clinics.getById('clinic-123');

// Private - must be logged in
const assigned = await api.clinics.getAssignedClinics('auth0|abc123');
await api.clinics.linkStaff('clinic-123', { auth0Id: 'auth0|abc123', id: 'user-456' });
await api.clinics.updateClinic('clinic-123', { name: 'New Name' });
await api.clinics.removeStaff('clinic-123', 'staff-789');
```

---

### `QueueService`

Base path: `/queues`.

| Method | auth | Server route |
|---|---|---|
| `getForPatient(patientAuth0Id)` | Private | `GET /api/queues/patient/:auth0Id` |
| `addPatient(clinicId, patientId, specialityName)` | Public | `POST /queues/` |
| `remove(queueId)` | Private | `DELETE /api/queues/:queueId` |
| `update(queueId, {clinicId, specialityId, patientId, status, remarks, timeSeen})` | Private | `PUT /api/queues/:queueId` |
| `get(clinicId, {auth0Id, userId, specialityIDs, statuses})` | Private | `GET /api/queues/:clinicId?statuses=...` with <br> `&auth0Id=..`,  `&userId=..`, or `&specialityIDs=spec1,spec2...`|


**Example usage in a component**
```js
const api = useApi();

// Get for Patient
const queuePatient = await api.queues.getForPatient("auth0|123");

// Get
const queue = await api.queues.get('clinicId', {userId: "user123", statuses: ["Waiting", "In Consult"]}); // statuses optional, will only filter if some are given
const queue = await api.queues.get('clinicId', {auth0Id: "auth0|456"});
const queue = await api.queues.get('clinicId', {specialityIDs: "GP,Maternity"});      // use comma separated names,
const queue = await api.queues.get('clinicId', {specialityIDs: ["GP","Maternity"]});  // or array of names

// Update (pass all fields to replace queue doc)
await api.queues.update('queue123', {clinicId: "clin1", specialityId: "spec1", patientId: "pat1", status: "Cancelled", remarks: "Rude to staff"});

// Add patient to queue
await api.queues.addPatient({ clinicId: "clin1", specialityId: "spec1", patientId: "pat1" });
```

---

### `SpecialityService`

Base path: `/specialities`.

| Method | auth | Server route |
|---|---|---|
| `addToStaff({staffId, specialityId})`| Private | `POST /api/specialities/staff/:staffId/:specialityId` |
| `removeFromStaff({staffId, specialityId})`| Private |`DELETE /api/specialities/staff/:staffId/:specialityId` |
| `getForStaff(staffId)`| Public | `GET /specialities/staff/:staffId` |

**Example usage in a component**
```js
const api = useApi();

// add speciality to staff
await api.specialities.addToStaff({staffId: "staff123", specialityId: "spc1"});

// remove speciality from staff
await api.specialities.removeFromStaff({staffId: "staff123", specialityId: "spc1"});

// get a list of staff specialities
const staffSpecs = await api.specialities.getForStaff("staff123");
```

---

### `ScheduleService`

Base path: `/schedules`. All methods are login protected.

| Method | Server route |
|---|---|
| `getSchedule(userId)` | `GET /api/schedules/:userId` |
| `update(scheduleId, {Staff, DayOfWeek, StartTime, EndTime})` | `PUT /api/schedules/:scheduleId` |

**Example usage in a component**
```js
const api = useApi();

// get a staff's schedule
const schedule = await api.schedules.getSchedule("user123");

// update a specific schedule entry
await spi.schedules.update("schdl1", {
  Staff: "user123",
  DayOfWeek: 0,
  StartTime: "01:00",
  EndTime: "23:00"
});
```

---

### `AppointmentService`

Base path: `/appointments`.

| Method | auth | Server route |
|---|---|---|
| `cancel(appointmentId)`| Private | `DELETE /api/appointments/:appointmentId` |
| `create({clinicId, staffUserId, patientAuth0Id, bookingDateTime, description, specialityName})`| Private |`POST /api/appointments/` |
| `getForAuth0Id(auth0Id)`| Private | `GET /api/appointments/:auth0Id?statuses=...` |
| `update(appointmentId, {patientUID, staffUID, clinicId, bookingDateTime, specialityId})`| Private | `PUT /api/appointments/:appointmentId` |

**Example usage in a component**
```js
const api = useApi();

// create appointment
await api.appointments.create({
  clinicId: "clnc1",
  staffUserId: "stff1",
  patientAuth0Id: "auth0|123",
  bookingDateTime: new Date().toISOString();
  description: "My elbow smells funny :(",
  specialityName: "General Checkup",
});

// update appointment
await api.appointments.update("appt1", {
  patientUID: "auth0|123",
  status: "In Consult"
})

// cancel appointment
await api.appointments.cancel("appt1");

// get a list of upcoming appointments by auth0Id
const appointments = await api.appointments.getForAuth0Id("auth0|123", {statuses: ["Waiting"]});
```
---

### `ConsultService`

Base path: `/consults`. All routes are private.

| Method | auth | Server route |
|---|---|---|
| `getForAuth0Id(auth0Id)` | Private | `GET /api/consults/:auth0Id` |

**Example usage in a component**
```js
const api = useApi();

// get consults for a user
const consults = await api.consults.getForAuth0Id("auth0|123");
```

---

## How to Create a New Service

Follow this pattern for `ScheduleService`, `AppointmentService`, `QueueService` and `SpecialityService`.

**1. Create the file** at `src/api/services/YourService.js`

```js
import {ResourceService} from '../ResourceService';

export class YourService extends ResourceService {
  constructor(pub, priv) {
    super(pub, priv, '/your-base-path'); // e.g. '/clinics'
  }

  // EXAMPLE METHODS
  // Public route - use this.pub
  getAll(params) {
    return this.pub.get(this.basePath, params);
  }

  // Private route - use this.priv
  create(body) {
    return this.priv.post(this.basePath, body, null);
  }

  // Route with both body and query params
  updateWithFilter(id, body, params) {
    return this.priv.patch(`${this.basePath}/${id}`, body, params);
  }
}
```

**2. Add it to `useApi.js`**

```js
import { YourService } from './services/YourService';

// inside useMemo return:
yourThing: new YourService(pub, priv),
```

**Rules:**
- Use `this.pub` for unprotected routes (no login requried)
- Use `this.priv` for routes that require a JWT token (`/api...`)
- Client method parameters are always `(url, body, params)` - except `GET` which is `(url, params)`
- Pass `null` explicitly when skipping body but including params - `(url, null, params)`
- Name methods after what they do, not the HTTP verb - `getAssignedClinics` not `getWithAuth0Id`
- Pass objects for bodies, not individual arguments - `update({ name, surname })` or `update(userObject)` not `update(name, date)`

---

## Error Handling

`ApiClient` throws an `ApiError` when the server returns a not ok response.

```js
// handling errors
try {
  await api.clinics.updateClinic(id, updates);
} catch (err) {
  if (err.status === 404) // not found
  if (err.status === 403) // unauthorized
  console.error(err.message);
}
```

---

## Known Problems to fix

These are tracked in the service files with `// TODO` comments. We need to fix routes or logic server side for all.

| Issue | Location |
|---|---|
| `auth0Id` for verification should come from JWT token or `/:auth0Id`, not request body | `ClinicService.linkStaff`, `ClinicService.linkAdmin`, `UserService.register` |
| `updateClinic` should use `PATCH` not `PUT` | `ClinicService.updateClinic` |
| `getAssignedClinics` route should use `/:staffId` param not query | `ClinicService.getAssignedClinics` |
| `linkAdmin` route should be renamed on server (currently `createClinic`) | `ClinicService.linkAdmin` |
| `getAssignedClinic` in server is redundant, `listAssignedClinics` should be used | Duplicate Server routes |
| `getStaffSpecialities` in server should be under `/specialities` service | Server route |
| `clinicInfo` in server is redundant | Duplicate Server routes |
| `hooks/useApi.js` will no longer be needed | client/src/hooks/ |
| `updateAppointment` should also include description field | `AppointmentService.update` |
| `createAppointment` fix naming convention | `AppointmentService.create` |

Please add other problems you come across here.
