# whoseeme

**See what a stranger could link to you.**

You give it your usernames. It checks ~840 sites, you pick out the accounts that are
actually yours, and it shows what ties them together: the same profile picture, a
bio that links to another account, your real name in a title, the same handle
everywhere. For each account it links the page where you can delete it.

It runs entirely on your computer. Your usernames go only to the sites being
checked, from your own connection. Nothing is uploaded, stored, or shared.

```bash
pip install whoseeme
whoseeme
```

That opens the app in your browser.

## How it works

1. **Scan.** Your usernames are checked across the site catalogue of
   [Aliens Eye](https://github.com/arxhr007/Aliens_eye), the engine this is built on.
2. **You confirm.** A common username matches hundreds of accounts belonging to
   other people, so a search result is not your exposure. You mark one or two
   accounts you know are yours.
3. **It follows the evidence.** From those accounts it traces only concrete links
   to others on *different* services:
   - **same picture**: near-identical images with enough detail to be a real
     photo, not a site logo
   - **bio links**: one profile links to another
   - **mentions**: one profile @-mentions another handle of yours
   - **same name**: an identical name that looks like a real person's
4. **Report.** Findings by severity, how each account connects to the others, and
   deletion instructions per account. It exports to HTML or JSON.

There is no single "privacy score". One number would imply more precision than a
handful of heuristics has, so you get the concrete findings instead.

## Headless

```bash
whoseeme audit yourhandle --anchor https://github.com/yourhandle --html report.html
```

`--anchor` is a profile URL you know is yours. Repeat it for several.

## Limits, honestly

- **Detection is imperfect.** The scanner favours fewer false leads over catching
  every account: on sites it was never trained on, about 9% of absent accounts
  still show up as found, and about half of real accounts are missed. The
  "not linked to you" list will contain other people's accounts.
- **The rules are heuristics.** "Looks like a real name" is a guess from its
  shape. Phone-number detection is a pattern match.
- **This is the same capability as any username search tool.** Calling it a
  self-audit doesn't stop someone pointing it at another person, and this README
  won't pretend it does. It adds nothing a determined person couldn't already do
  with existing tools; its purpose is to show you your own exposure first.

## Security

The app is a local web server, and any page you visit can send requests to
`localhost`. So it listens on `127.0.0.1` only, rejects requests whose `Host`
isn't its own address (which blocks DNS rebinding), requires a random token minted
at startup on every API call, and sets a strict Content-Security-Policy. Text from
scanned pages is always rendered as inert text. Avatar images are only fetched
from public addresses and are never shown in the browser, so opening your report
doesn't notify anyone.

## Credits

Account-deletion guidance comes from [JustDeleteMe](https://github.com/jdm-contrib/jdm)
(MIT); see `src/whoseeme/data/LICENSE-JDM`. Refresh it with
`python scripts/update_jdm.py`.

## License

MIT
