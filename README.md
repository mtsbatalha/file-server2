# File Server Manager

Sistema completo de gerenciamento de servidores de arquivos com suporte a múltiplos protocolos (FTP, SFTP, SMB, NFS, WebDAV), interface web moderna e segurança avançada.

## Funcionalidades

### Serviços de Arquivos
- **FTP** - File Transfer Protocol com suporte a TLS/SSL
- **SFTP** - SSH File Transfer Protocol
- **SMB/CIFS** - Server Message Block para compartilhamento Windows
- **NFS** - Network File System para ambientes Unix/Linux
- **WebDAV** - Web-based Distributed Authoring and Versioning

### Gerenciamento
- Dashboard com visão geral do sistema
- Gerenciamento de usuários e permissões (RBAC)
- Configuração de compartilhamentos
- Logs e auditoria em tempo real
- Backup automatizado

### Segurança
- Autenticação JWT com refresh tokens
- Firewall UFW configurado automaticamente
- Fail2Ban para proteção contra brute force
- Hardening SSH
- HTTPS/TLS obrigatório
- Políticas de senha forte

## Arquitetura

```
file-server5/
├── backend/                 # API FastAPI
│   ├── app/
│   │   ├── models/         # Modelos SQLAlchemy
│   │   ├── routers/        # Endpoints da API
│   │   ├── security/       # Autenticação e segurança
│   │   └── services/       # Gerenciadores de serviço
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/               # Interface React
│   ├── src/
│   │   ├── components/    # Componentes reutilizáveis
│   │   ├── pages/         # Páginas da aplicação
│   │   ├── stores/        # Estado global (Zustand)
│   │   └── lib/           # Utilitários
│   ├── package.json
│   └── Dockerfile
└── docker-compose.yml
```

## Requisitos

- Docker e Docker Compose
- Ou Python 3.11+ e Node.js 18+ para desenvolvimento local

## Instalação

### Usando Docker (Recomendado)

```bash
# Clonar o repositório
git clone <repository-url>
cd file-server5

# Configurar variáveis de ambiente
cp .env.example .env
# Editar .env com suas configurações

# Iniciar os serviços
docker-compose up -d

# Acessar a aplicação
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Desenvolvimento Local

#### Backend

```bash
cd backend

# Criar ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou .\venv\Scripts\activate  # Windows

# Instalar dependências
pip install -r requirements.txt

# Executar migrations
alembic upgrade head

# Iniciar servidor
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Frontend

```bash
cd frontend

# Instalar dependências
npm install

# Iniciar servidor de desenvolvimento
npm run dev
```

## Configuração

### Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto:

```env
# Backend
DATABASE_URL=sqlite:///./data/fileserver.db
JWT_SECRET_KEY=your-super-secret-key-change-this
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Frontend
VITE_API_URL=http://localhost:8000
```

### Configuração de Banco de Dados

O sistema suporta múltiplos bancos de dados:

#### SQLite (Padrão)
```env
DATABASE_URL=sqlite:///./data/fileserver.db
```

#### MySQL Remoto (Recomendado para Produção)
```env
# Opção 1: Usar variáveis individuais
MYSQL_HOST=seu-servidor-mysql.com
MYSQL_PORT=3306
MYSQL_USER=seu_usuario
MYSQL_PASSWORD=sua_senha
MYSQL_DATABASE=fileserver

# Opção 2: Usar DATABASE_URL diretamente
DATABASE_URL=mysql+pymysql://usuario:senha@host:3306/fileserver?charset=utf8mb4
```

#### PostgreSQL
```env
DATABASE_URL=postgresql://usuario:senha@host:5432/fileserver
```

#### MySQL Local com Docker
Para usar um container MySQL local, descomente a seção `mysql` no `docker-compose.yml`:

```yaml
mysql:
  image: mysql:8.0
  container_name: fileserver-manager-mysql
  restart: unless-stopped
  environment:
    - MYSQL_ROOT_PASSWORD=rootpassword
    - MYSQL_DATABASE=fileserver
    - MYSQL_USER=fileserver
    - MYSQL_PASSWORD=fileserver123
  ports:
    - "3306:3306"
  volumes:
    - mysql_data:/var/lib/mysql
```

Depois configure as variáveis de ambiente:
```env
MYSQL_HOST=mysql
MYSQL_PORT=3306
MYSQL_USER=fileserver
MYSQL_PASSWORD=fileserver123
MYSQL_DATABASE=fileserver
```

### Usuário Padrão

O sistema cria automaticamente um usuário administrador:

- **Usuário:** admin
- **Senha:** admin123

⚠️ **Importante:** Altere a senha padrão após o primeiro acesso!

## API Endpoints

### Autenticação
- `POST /api/auth/login` - Login
- `POST /api/auth/refresh` - Renovar token
- `POST /api/auth/logout` - Logout

### Serviços
- `GET /api/services` - Listar serviços
- `POST /api/services` - Criar serviço
- `GET /api/services/{id}` - Detalhes do serviço
- `PUT /api/services/{id}` - Atualizar serviço
- `DELETE /api/services/{id}` - Remover serviço
- `POST /api/services/{id}/start` - Iniciar serviço
- `POST /api/services/{id}/stop` - Parar serviço
- `POST /api/services/{id}/restart` - Reiniciar serviço

### Usuários
- `GET /api/users` - Listar usuários
- `POST /api/users` - Criar usuário
- `GET /api/users/{id}` - Detalhes do usuário
- `PUT /api/users/{id}` - Atualizar usuário
- `DELETE /api/users/{id}` - Remover usuário

### Compartilhamentos
- `GET /api/shares` - Listar compartilhamentos
- `POST /api/shares` - Criar compartilhamento
- `GET /api/shares/{id}` - Detalhes do compartilhamento
- `PUT /api/shares/{id}` - Atualizar compartilhamento
- `DELETE /api/shares/{id}` - Remover compartilhamento

### Sistema
- `GET /api/system/stats` - Estatísticas do sistema
- `GET /api/system/config` - Configurações
- `PUT /api/system/config` - Atualizar configurações

### Logs
- `GET /api/logs` - Listar logs
- `GET /api/logs/ws` - WebSocket para logs em tempo real

## Desenvolvimento

### Estrutura de Código

O projeto segue princípios de Clean Architecture:

- **Models:** Definição de dados e schemas
- **Routers:** Endpoints da API
- **Services:** Lógica de negócio
- **Security:** Autenticação e autorização

### Padrões Utilizados

- Repository Pattern
- Dependency Injection
- RBAC (Role-Based Access Control)
- RESTful API Design

### Testes

```bash
# Backend
cd backend
pytest

# Frontend
cd frontend
npm run test
```

## Segurança

### Firewall

O sistema configura automaticamente o UFW com as seguintes regras:
- SSH (22)
- HTTP/HTTPS (80, 443)
- FTP (20, 21, 40000-50000)
- SFTP (22)
- SMB (139, 445)
- NFS (111, 2049)

### Fail2Ban

Proteção contra ataques de força bruta configurada para:
- SSH
- FTP
- SMB

### Hardening

- Desabilitado login root via SSH
- Autenticação por chave SSH recomendada
- Senhas fortes obrigatórias
- Rate limiting na API

## Backup

O sistema realiza backups automáticos de:
- Banco de dados
- Configurações
- Logs

Configuração em `/var/backups/fileserver-manager/`

## Troubleshooting

### Serviço não inicia

```bash
# Verificar logs
docker-compose logs backend

# Verificar status
docker-compose ps
```

### Erro de permissão

```bash
# Ajustar permissões
sudo chown -R $USER:$USER data/
```

### Reset do banco de dados

```bash
# Parar serviços
docker-compose down

# Remover volume
docker volume rm fileserver-manager_backend_data

# Reiniciar
docker-compose up -d
```

## Licença

MIT License

## Contribuição

1. Fork o projeto
2. Crie sua branch (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request