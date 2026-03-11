# codo-admin 安全漏洞报告

**报告日期**：2025-03-11  
**目标项目**：codo-admin（CODO 管理后台）  
**审计方式**：代码审计 + PoC 复现验证  

---

## 一、项目简介

### 1.1 项目概述

codo-admin 是 CODO 开源 DevOps 平台的管理后台服务，基于 **Tornado** 框架实现 RESTful 风格 API，提供登录/注册、用户与角色管理、权限与菜单管理、前端组件与路由管理、通知服务、系统基础信息等能力。前端为 admin-f（iView + Vue），本项目作为后台 API 为 CODO 全平台提供鉴权与系统管理支持。

- **项目仓库**：opendevops-cn/codo-admin  
- **在线演示**：http://demo.opendevops.cn/  

### 1.2 技术栈

| 类别     | 技术 |
|----------|------|
| 语言     | Python 3 |
| Web 框架 | Tornado（websdk2 封装） |
| 数据库   | MySQL + SQLAlchemy 2.0.20 |
| 缓存     | Redis |
| 认证     | JWT（Cookie auth_key / refresh_token）、TOTP、LDAP / 飞书 / 钉钉 / 企微 |
| 存储     | 阿里云 OSS（oss2）、腾讯云 COS（cos-python-sdk-v5） |

### 1.3 关键目录与入口

- **主入口**：`startup.py`（通过 fire 解析 `--service` 启动 mg-api / admin-mg-api 等）
- **配置**：`settings.py`（数据库、Redis、Cookie/Token 密钥等，支持 `local_settings` 覆盖）
- **API 路由**：`mg/applications.py` 聚合 `mg/handlers/` 下各模块路由
- **业务逻辑**：`services/`（用户、角色、菜单、登录、存储、审计等）
- **通用工具**：`libs/`（BaseHandler 鉴权、对象存储、第三方登录、etcd 等）

---

