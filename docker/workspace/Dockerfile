FROM debian:bookworm

SHELL ["/bin/bash", "-c"]

ARG ASDF_VERSION=v0.14.0
ARG DIRENV_VERSION=2.34.0
ARG NODE_VERSION=22.14.0

RUN apt-get update -y && apt-get install -y \
  curl gcc make git zip unzip jq openssl ca-certificates gnupg lsb-release groff default-mysql-client pass gnupg2 iproute2 iputils-ping

RUN curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
  && echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
  && apt-get update -y && apt-get -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin

RUN git clone https://github.com/asdf-vm/asdf.git ~/.asdf --branch ${ASDF_VERSION} \
  && echo '. ~/.asdf/asdf.sh' >> ~/.bash_profile \
  && echo '. ~/.asdf/completions/asdf.bash' >> ~/.bash_profile \
  && echo 'asdf direnv setup --shell bash --version ${DIRENV_VERSION}' >> ~/.bash_profile \
  && . ~/.asdf/asdf.sh \
  && . ~/.asdf/completions/asdf.bash \
  && asdf plugin-add direnv https://github.com/asdf-community/asdf-direnv.git \
  && asdf direnv setup --shell bash --version ${DIRENV_VERSION} \
  && asdf global direnv ${DIRENV_VERSION} \
  && asdf plugin-add awscli https://github.com/MetricMike/asdf-awscli.git \
  && asdf install awscli latest:2 \
  && asdf global awscli latest \
  && asdf plugin-add aws-vault https://github.com/karancode/asdf-aws-vault.git \
  && asdf install aws-vault latest \
  && asdf global aws-vault latest \
  && echo 'export GPG_TTY="$(tty)"' >> ~/.bashrc \
  && asdf plugin add nodejs https://github.com/asdf-vm/asdf-nodejs.git \
  && asdf install nodejs ${NODE_VERSION} \
  && echo 'eval "$(direnv hook bash)"' >> ~/.bashrc \
  && /root/.asdf/shims/aws configure set credential_process "aws-vault exec dev --json --prompt=terminal --duration 1h" --profile dev \
  && /root/.asdf/shims/aws configure set credential_process "aws-vault exec stage --json --prompt=terminal --duration 1h" --profile stage \
  && /root/.asdf/shims/aws configure set credential_process "aws-vault exec prod --json --prompt=terminal --duration 1h" --profile prod

WORKDIR /work/ts-t3-sample
