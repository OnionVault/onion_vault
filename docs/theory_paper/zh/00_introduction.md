# 1 引言（Introduction）

- ## 1.1 研究背景和动机
我的研究动机源于我在没有网络和言论自由的环境下生活过的深刻体验。在这样的国家，安全通信和隐私保护不仅仅是"卫生习惯"，更是为所有自己在乎的人争取光明未来必须做的事情。我亲身参与通过技术手段挑战独裁统治的经历，使我对密码管理和隐私保护有了不少体验和思考。

- ## 1.2 论文目标与声明
本文并不是要提出完美无瑕的方案，而是想提供比市场上现有方案更安全、更符合人体工学的密码管理方案。
本文期待解决的问题：既要高安全性，又要符合人类认知习惯，降低用户负担。

- ## 1.3 为什么不使用传统的密码管理方案

密码管理器的核心价值在于生成高熵密码并避免密码复用，从而降低被攻击的风险。然而，现有的密码管理器，无论是商业的（如Google和Apple）还是开源的（如Bitwarden和KeePass），都存在一些说大不大说小也不小的[安全隐患](01_existing_solutions.md#12-%E9%9D%9E%E5%BC%80%E6%BA%90%E5%AF%86%E7%A0%81%E7%AE%A1%E7%90%86%E5%99%A8%E5%A6%82googleapplesamsung1password)。这将在第二部分详细讨论

硬件密钥（如通过FIDO2）提供了一种替代方案，显著降低了攻击面，但也面临诸如实施不完善、备份困难和用户验证不足等问题。另一方面，支持FIDO2的硬件加密货币钱包（如Trezor）通过其开源特性、用户操作确认机制和强大的备份方案，展示了在密码管理领域的巨大潜力。

- ## 1.4 本文提供的新方案 OnionVault
基于这些观察和经验，我提出了一个结合硬件钱包和密码管理的新方案并开发了Beta版以及将之开源，旨在为需要安全和隐私的人提供更高效的保护。本文将详细探讨：

- [现有密码管理解决方案的优点与不足](01_existing_solutions.md)。
- 基于Trezor硬件钱包的密码管理[新方案](02_proposed_solution.md#22-%E6%9C%AC%E6%96%87%E7%AC%AC%E4%B8%80%E4%BD%9C%E8%80%85%E4%B8%BAtrezor%E5%BC%80%E5%8F%91%E7%9A%84%E5%AF%86%E7%A0%81%E7%AE%A1%E7%90%86%E5%99%A8-onionvault)。
- 新方案具备的新安全特性和其他(某些密码管理器甚至都没好好实现的)实用[特性](./02_proposed_solution.md#23-%E6%96%B0%E7%9A%84%E5%AF%86%E7%A0%81%E7%AE%A1%E7%90%86%E6%96%B9%E6%A1%88onionvault%E5%85%B7%E5%A4%87%E5%A6%82%E4%B8%8Bfeatures)。
- 用户体验和实用性的考虑 [不需要记忆和输入密码就可以使用](02_proposed_solution.md#%E6%AF%94%E5%AF%86%E7%A0%81%E7%AE%80%E5%8D%95) [自动输入密码](02_proposed_solution.md#password-auto-fill) [用备份助记词代替记忆密码](02_proposed_solution.md#%E5%8F%AF%E4%BB%A5%E4%B8%8D%E7%94%A8%E8%AE%B0%E5%BF%86%E5%AF%86%E7%A0%81)。
- [未来的开发方向](02_proposed_solution.md#24-onionvault%E7%9A%84%E6%9C%AA%E6%9D%A5)。
- [附录和FAQ](03_appendix_faq.md)

通过此研究，我希望能为所有人提供更为安全、可靠的工具，帮助他们在不被监控和攻击的情况下，自由地分享信息和观点。


| [下一页](01_existing_solutions.md) |
|-----------------------------------|
