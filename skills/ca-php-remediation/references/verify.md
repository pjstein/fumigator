# Verifying a fix

A fix is proven when the client **fails** to fetch the community test hosts. Both must fail: the
first chains through eMudhra's own root, the second through Sectigo's AAA cross-sign, and a client
that only dropped one still trusts the other.

```
https://dv-g3b-emudhra.we-have-a-problem.com/
https://dv-g3b-aaa-emudhra.we-have-a-problem.com/
```

A successful fetch returns a page that literally says "That's bad!". A certificate error is the
good outcome. Make sure the check is actually running the client you think it is — a wrapper
function that swallows the command name will report "rejects" for everything.

## Built images

```bash
docker build --pull --no-cache -t verify:tmp .
# Debian/Ubuntu/Alpine with curl:
docker run --rm verify:tmp sh -c 'curl -sSf https://dv-g3b-emudhra.we-have-a-problem.com/ && echo STILL_TRUSTS'
# Alpine without curl:
docker run --rm verify:tmp sh -c 'wget -qO- https://dv-g3b-emudhra.we-have-a-problem.com/ && echo STILL_TRUSTS'
# Python image:
docker run --rm verify:tmp python -c "import ssl,certifi,urllib.request as u; u.urlopen('https://dv-g3b-emudhra.we-have-a-problem.com/', context=ssl.create_default_context(cafile=certifi.where())); print('STILL_TRUSTS')"
# Node image:
docker run --rm verify:tmp node -e "fetch('https://dv-g3b-emudhra.we-have-a-problem.com/').then(()=>console.log('STILL_TRUSTS'),()=>{})"
# Go binary in a scratch/distroless image — build a tiny checker into the image or test the binary's Go version:
go version -m ./app | head -1      # must show go1.26.10+ / go1.27.3+
```

Nothing printed = fixed. `STILL_TRUSTS` = the image still trusts the chain: usually a cached base
layer (`--pull --no-cache` not used), a `COPY`'d bundle from an unfixed builder stage, or a runtime
that carries its own roots (Node, Python certifi, Java) that the OS package didn't touch.

## PHP

```bash
php -v                                     # ≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
php -i | grep -E 'session.upload_progress.enabled|memory_limit|post_max_size'
```

On a server you can't update today, `session.upload_progress.enabled = 0` must be in `php.ini` or
the FPM pool (not `.user.ini`, not `ini_set`) and every worker restarted. PHP's own position: no
mitigation is complete; only the update is.

## Offline

[chains.zip](https://emudhra.we-have-a-problem.com/chains.zip) has the twelve served chains as PEM
with OpenSSL instructions, for checking a bundle file without network access:

```bash
openssl verify -CAfile /path/to/bundle.pem chain.pem    # "OK" = still trusts
```

## Don't over-block

After any bundle edit: `curl -sSI https://github.com https://pypi.org https://registry.npmjs.org >/dev/null && echo fine`.
Removing *AAA Certificate Services* can break a site that chains only to that Sectigo root; nearly
all cross-chain to another root, but check before shipping a stripped bundle into production.
