# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal fixed complete captured CWE terms-page text and technical extraction provenance."""

from __future__ import annotations

import json
from typing import cast

__all__ = ()

NOTICE_PROFILE = "cwe-terms-complete-page-20261103-v1"
_BUNDLE_JSON = (
    '{"legal_rights":"not-assessed","notice_applicability":"not-assessed","profil'
    'e":"cwe-terms-complete-page-20261103-v1","provenance":{"encoding":"strict UT'
    'F-8; HTML declares utf-8","extraction_profile":"complete-html-text-v1","extr'
    'actor":{"path":"extract_page.py","sha256":"2ef24e27335dde69ac124d06f7807d50f'
    '7361003586f9b70a9f2c035a38ddb13"},"http_status":200,"observed_page_update_li'
    'nes":["Page Last Updated:","July 20, 2023"],"observed_url":"https://cwe.mitr'
    'e.org/about/termsofuse.html","raw_html":{"bytes":17670,"path":"response.html'
    '","sha256":"c572b605b5753cd67b84d12fc64e9ccbfcde0188cf1332118be04c9996a92c45'
    '"},"retrieved_at":"2026-11-03T17:44:02.196900+00:00","rules":["HTMLParser(co'
    'nvert_charrefs=True), document order","exclude script/style text and HTML co'
    'mments; do not execute code, styles or resources","retain all other text inc'
    'luding hidden/noscript content; add image alt values with explicit marker","'
    'insert newlines at fixed block tags, collapse whitespace per line and remove'
    ' blank lines","no Unicode normalization, legal interpretation, selective not'
    'ice trimming or footer removal","retain all href/src/action values with raw '
    'value, source coordinates and resolved display locator; never fetch links"],'
    '"scope":"all document text nodes including head title, navigation, terms, di'
    'sclaimers and footer; no section selection","source_response_version":{"date'
    '":"Tue, 03 Nov 2026 17:44:02 GMT","etag":null,"last_modified":null},"source_'
    'url":"https://cwe.mitre.org/about/termsofuse.html","text_extract":{"bytes":4'
    '329,"path":"page-text.txt","sha256":"d1595d0a2bc408587d9d3ba24974e3815474007'
    '72693635d4b340f225e068c2f"}},"publisher_authentication":"not-assessed","text'
    '":"CWE -\\nTerms of Use\\n[image alt: CWE]\\nCommon Weakness Enumeration\\nCeleb'
    'rating 20 years of community-developed cybersecurity weakness knowledge!\\n[i'
    'mage alt: New to CWE? click here!]\\n[image alt: CWE Most Important Hardware '
    'Weaknesses]\\n[image alt: CWE Top 25 Most Dangerous Weaknesses]\\nHome > About'
    ' CWE >\\nTerms of Use\\nID Lookup:\\nHome\\nAbout ▼\\nWho We Are\\nUser Stories\\nH'
    'istory\\nDocuments\\nVideos\\nLearn ▼\\nBasics\\nRoot Cause Mapping ►\\nGuidance\\n'
    'Quick Tips\\nExamples\\nHow to Contribute Weakness Content\\nFAQs\\nGlossary\\nAc'
    'cess Content ▼\\nTop-N Lists ►\\nTop 25 Software\\nTop Hardware\\nTop 10 KEV Wea'
    'knesses\\nCWE List ►\\nCurrent Version\\nReports\\nVisualizations\\nReleases Arch'
    'ive\\nDownloads\\nREST API\\nCommunity ▼\\nNews ►\\nCurrent News\\nBlog\\nPodcast\\n'
    'News Archive\\nCWE Board\\nWorking Groups & Special Interest Groups\\nEmail Lis'
    'ts\\nSearch ▼\\nSearch CWE List\\nSearch Website\\nCWE Glossary Definition\\n[ima'
    'ge alt: x]\\nTerms of Use\\nCWE™ is free to use by any organization or individ'
    'ual for any research, development, and/or commercial purposes, per these CWE'
    ' Terms of Use. Accordingly, The MITRE Corporation hereby grants you a non-ex'
    'clusive, royalty-free license to use CWE for research, development, and comm'
    'ercial purposes. Any copy you make for such purposes is authorized on the co'
    'ndition that you reproduce MITRE’s copyright designation and this license in'
    ' any such copy. CWE is a trademark of The MITRE Corporation. Please contact '
    'cwe@mitre.org if you require further clarification on this issue.\\nDISCLAIME'
    'RS\\nBy accessing information through this site you (as “the user”) hereby ag'
    'rees the site and the information is provided on an “as is” basis only witho'
    'ut warranty of any kind, express or implied, including but not limited to im'
    'plied warranties of merchantability, availability, accuracy, noninfringement'
    ', or fitness for a particular purpose. Use of this site and the information '
    'is at the user’s own risk. The user shall comply with all applicable laws, r'
    'ules, and regulations, and the data source’s restrictions, when using the si'
    'te.\\nBy contributing information to this site you (as “the contributor”) her'
    'eby represents and warrants the contributor has obtained all necessary permi'
    'ssions from copyright holders and other third parties to allow the contribut'
    'or to contribute, and this site to host and display, the information and any'
    ' such contribution, hosting, and displaying will not violate any law, rule, '
    'or regulation. Additionally, the contributor hereby grants all users of such'
    ' information a perpetual, worldwide, non-exclusive, no-charge, royalty-free,'
    ' irrevocable license to reproduce, prepare derivative works of, publicly dis'
    'play, publicly perform, sublicense, and distribute such information and all '
    'derivative works.\\nThe MITRE Corporation expressly disclaims any liability f'
    'or any damages arising from the contributor’s contribution of such informati'
    'on, the user’s use of the site or such information, and The MITRE Corporatio'
    'n’s hosting the tool and displaying the information. The foregoing disclaime'
    'r specifically includes but is not limited to general, consequential, indire'
    'ct, incidental, exemplary, or special or punitive damages (including but not'
    ' limited to loss of income, program interruption, loss of information, or ot'
    'her pecuniary loss) arising out of use of this information, no matter the ca'
    'use of action, even if The MITRE Corporation has been advised of the possibi'
    'lity of such damages.\\nPage Last Updated:\\nJuly 20, 2023\\n[image alt: MITRE]'
    '\\nSite Map |\\nTerms of Use |\\nManage Cookies |\\nCookie Notice |\\nPrivacy Pol'
    'icy |\\nContact Us |\\n[image alt: CWE on X]\\n[image alt: CWE on LinkedIn]\\n[i'
    'mage alt: CWE on Bluesky]\\n[image alt: CWE on Mastodon]\\n[image alt: CWE You'
    'Tube channel]\\n[image alt: CWE Out-of-Bounds-Read Podcast]\\n[image alt: CWE '
    'Blog on Medium blog]\\nUse of the Common Weakness Enumeration (CWE™) and the '
    'associated references from this website are subject to the Terms of Use. CWE'
    ' is sponsored by the U.S. Department of Homeland Security (DHS) Cybersecurit'
    'y and Infrastructure Security Agency (CISA) and managed by the Homeland Secu'
    'rity Systems Engineering and Development Institute (HSSEDI) which is operate'
    'd by The MITRE Corporation (MITRE). Copyright © 2006–2026, The MITRE Corpora'
    'tion. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corpora'
    'tion.\\n[image alt: HSSEDI]\\n"}'
)


def CweNoticeBundle() -> dict[str, object]:
    """Return detached complete captured page text and explicit assessment limitations.

    Returns:
        One versioned immutable-by-value bundle with complete terms, disclaimers and footer.
    """

    return cast(dict[str, object], json.loads(_BUNDLE_JSON))
