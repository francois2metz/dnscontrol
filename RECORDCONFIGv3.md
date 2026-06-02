
DELETE THIS BEFORE THE RELEASE

### Release Notes:

* Replacing github.com/miekg/dns (v1) with codeberg.org/miekg/dns (v2).
* RecordConfigV3: We're adopting codeberg.org/miekg/dns in a big way!  It's now the prefered way to store a DNS record.  RecordConfig.RDATA stores a dns.RDATA interface, which can contain any DNS record type, even unofficial ones. This should save memory in the long run, but at this time it means storing a lot of data twice until legacy code is upgraded.

### Extra testing needed:

* BIND: SOA handling has been rewritten to be easier to debug and more reliable. Shouldn't have any user-visible changes but please be on the lookout.

### Developer notes

* There is now a factory for `models.DomainConfig{}` called `models.NewDomainConfig(name)`. This is now the only supported way to make a new `DomainConfig`.

### Potential breaking changes

### TODOs:

* `pkg/txtutil/{miekg.go miekg_test.go ddd/ddd.go}` come from dnsv2.  Upstream changes?
* Handle `ech=IGNORE` when it is ech=0000
* PTR magic should be implemented in pkg/js??

