![](https://i.imgur.com/xeKD93p.png)
[![Release 3.2.7](https://img.shields.io/badge/release-v3.2.7-green)](https://github.com/raspap/raspap-webgui/releases) [![Awesome](https://awesome.re/badge.svg)](https://github.com/thibmaek/awesome-raspberry-pi) [![Join Insiders](https://img.shields.io/static/v1?label=Insiders&message=%E2%9D%A4&logo=GitHub&color=ff69b4)](https://github.com/sponsors/RaspAP) [![Build Status](https://app.travis-ci.com/RaspAP/raspap-webgui.svg?branch=master)](https://app.travis-ci.com/RaspAP/raspap-webgui) [![Crowdin](https://badges.crowdin.net/raspap/localized.svg)](https://crowdin.com/project/raspap) [![Twitter URL](https://img.shields.io/twitter/url?label=%40RaspAP&logoColor=%23d8224c&url=https%3A%2F%2Ftwitter.com%2Frasp_ap)](https://twitter.com/rasp_ap) [![Reddit](https://img.shields.io/badge/%2Fr%2FRaspAP-e05d44?style=flat&logo=Reddit&logoColor=white&labelColor=e05d44&color=b14835)](https://reddit.com/r/RaspAP) [![Discord](https://img.shields.io/discord/642436993451819018?color=7289DA&label=Discord&logo=discord&style=flat)](https://discord.gg/KVAsaAR)


RaspAP is feature-rich wireless router software that _just works_ on many popular [Debian-based devices](#supported-operating-systems), including the Raspberry Pi. Our popular [Quick installer](#quick-installer) and [Docker container](#docker-support) create a known-good default configuration for all current Raspberry Pis with onboard wireless. A fully responsive, mobile-ready interface gives you control over the relevant services and networking options. Advanced DHCP settings, WireGuard and OpenVPN support, [SSL certificates](https://docs.raspap.com/ssl/), security audits, [captive portal integration](https://docs.raspap.com/captive/), themes and [multilingual options](https://docs.raspap.com/translations/) are included.

RaspAP has been featured on sites such as [Instructables](http://www.instructables.com/id/Raspberry-Pi-As-Completely-Wireless-Router/), [Adafruit](https://blog.adafruit.com/2016/06/24/raspap-wifi-configuration-portal-piday-raspberrypi-raspberry_pi/), [Raspberry Pi Weekly](https://www.raspberrypi.org/weekly/commander/) and [Awesome Raspberry Pi](https://project-awesome.org/thibmaek/awesome-raspberry-pi) and implemented in countless projects.

We hope you enjoy using RaspAP as much as we do creating it. Tell us how you use this with [your own projects](https://github.com/raspap/raspap-awesome).

![](https://github.com/user-attachments/assets/c9bb0386-0b10-48cc-8b42-0a587a84fc37)
<img width="32.5%" alt="Wifi Client" src="https://github.com/user-attachments/assets/95696ddc-da84-4339-97cc-f2a173054664">
<img width="32.5%" alt="Hotspot" src="https://github.com/user-attachments/assets/c1c4de15-3ff2-4d3c-a7af-339c24896749">
<img width="32.5%" alt="Adblock" src="https://github.com/user-attachments/assets/ab925687-8407-4bec-a952-9dc6a2675f49">
<img width="32.5%" alt="About" src="https://github.com/user-attachments/assets/ba62d8bb-34f0-44ee-9fe8-504763a03726">
<img width="32.5%" alt="Wireguard" src="https://github.com/user-attachments/assets/4ba16118-8671-4654-9a36-92ac7bc8507f">
<img width="32.5%" alt="System" src="https://github.com/user-attachments/assets/f54e04fc-dc2c-4a21-903b-23641795822b">

## Contents

 - [Prerequisites](#prerequisites)
 - [Quick installer](#quick-installer)
 - [Join Insiders](#join-insiders)
 - [WireGuard support](#wireguard-support)
 - [OpenVPN support](#openvpn-support)
 - [VPN Provider support](#vpn-provider-support)
 - [Ad Blocking](#ad-blocking)
 - [Bridged AP](#bridged-ap)
 - [Simultaneous AP and Wifi client](#simultaneous-ap-and-wifi-client)
 - [Manual installation](#manual-installation)
 - [802.11ac 5GHz support](#80211ac-5ghz-support)
 - [Supported operating systems](#supported-operating-systems)
 - [HTTPS support](#https-support)
 - [Docker support](#docker-support)
 - [Custom user plugins](#custom-user-plugins)
 - [Multilingual support](#multilingual-support)
 - [How to contribute](#how-to-contribute)
 - [Reporting issues](#reporting-issues)
 - [License](#license)

## Prerequisites
Start with a clean install of the [latest release of Raspberry Pi OS Lite](https://www.raspberrypi.com/software/operating-systems/). Both the 32- and 64-bit Lite versions are supported. The Raspberry Pi OS desktop distro is [unsupported](https://docs.raspap.com/faq/#distros).

1. Update Raspbian, including the kernel and firmware, followed by a reboot:
```
sudo apt-get update
sudo apt-get full-upgrade
sudo reboot
```
2. Set the "WLAN country" option in `raspi-config`'s **Localisation Options**: `sudo raspi-config`

3. If you have a device without an onboard wireless chipset, the [**Edimax Wireless 802.11b/g/n nano USB adapter**](https://www.edimax.com/edimax/merchandise/merchandise_detail/data/edimax/global/wireless_adapters_n150/ew-7811un) is an excellent option – it's small, cheap and has good driver support.

With the prerequisites done, you can proceed with either the Quick installer or Manual installation steps below.

## Quick installer
Install RaspAP from your device's shell prompt:
```sh
curl -sL https://install.raspap.com | bash
```
The [installer](https://docs.raspap.com/quick/) will complete the steps in the manual installation (below) for you.

After the reboot at the end of the installation the wireless network will be
configured as an access point as follows:
* IP address: 10.3.141.1
  * Username: admin
  * Password: secret
* DHCP range: 10.3.141.50 — 10.3.141.254
* SSID: `raspi-webgui`
* Password: ChangeMe

**Note:** As the name suggests, the Quick Installer is a great way to quickly setup a new AP. However, it does not automagically detect the unique configuration of your system. Best results are obtained by connecting to ethernet (`eth0`) or as a WiFi client, also known as managed mode, with `wlan0`. For the latter, refer to [this FAQ](https://docs.raspap.com/faq/#headless). Special instructions for the Pi Zero W are [available here](https://docs.raspap.com/ap-sta/).

Please [read this](https://docs.raspap.com/issues/) before reporting an issue.

## Join Insiders
[![](https://i.imgur.com/eml7k0b.png)](https://github.com/sponsors/RaspAP/)  

RaspAP is free software, but powered by _your_ support. If you find RaspAP useful for your personal or commercial projects, [become an Insider](https://github.com/sponsors/RaspAP/) and get early access to [exclusive features](https://docs.raspap.com/insiders/#exclusive-features) in the [Insiders Edition](https://docs.raspap.com/insiders/).

A tangible side benefit of sponsorship is that **Insiders** are able to help _steer future development of RaspAP_. This is done through Insiders' team access to discussions, feature requests, issues and more in the private GitHub repository.

## WireGuard support

![](https://i.imgur.com/5YDv37e.png)

WireGuard® is an extremely simple yet fast and modern VPN that utilizes state-of-the-art cryptography. It aims to be considerably more performant than OpenVPN, and is generally regarded as the most secure, easiest to use, and simplest VPN solution for modern Linux distributions.

WireGuard may be optionally installed by the [Quick Installer](https://docs.raspap.com/quick/). Once this is done, you can manage local (server) settings, create a peer configuration and control the `wg-quick` service with RaspAP.

Details are [provided here](https://docs.raspap.com/wireguard/).

## OpenVPN support

![](https://i.imgur.com/ta7tCon.png)

OpenVPN may be optionally installed by the Quick Installer. Once this is done, you can [manage client configurations](https://docs.raspap.com/openvpn/) and the `openvpn-client` service with RaspAP.

To configure an OpenVPN client, upload a valid .ovpn file and, optionally, specify your login credentials. RaspAP will store your client configuration and add firewall rules to forward traffic from OpenVPN's `tun0` interface to your configured wireless interface. 

See our [OpenVPN documentation](https://docs.raspap.com/openvpn/) for more information.

## VPN provider support

Several popular VPN providers include a Linux Command Line Interface (CLI) for interacting with their services. As a new beta feature, you may optionally control these VPN services from within RaspAP. After your provider's CLI is installed on your system you may administer it thereafter by using RaspAP's UI.

See our [VPN provider documentation](https://docs.raspap.com/providers/) for more information.

## Ad Blocking
This feature uses DNS blacklisting to block requests for ads, trackers and other undesirable hosts. To enable ad blocking, simply respond to the prompt during the installation. As a beta release, we encourage testing and feedback from users of RaspAP.

Details are [provided here](https://docs.raspap.com/adblock/).

## Bridged AP
By default RaspAP configures a routed AP for your clients to connect to. A bridged AP configuration is also possible. Slide the **Bridged AP mode** toggle under the **Advanced** tab of **Configure hotspot**, then save and restart the hotspot.

**Note:** In bridged mode, all routing capabilities are handled by your upstream router. Because your router assigns IP addresses to your device's hotspot and its clients, you might not be able to reach the RaspAP web interface from the default `10.3.141.1` address. Instead use your RPi's hostname followed by `.local` to access the RaspAP web interface. With Raspbian default settings, this should look like `raspberrypi.local`. Alternate methods are [discussed here](https://www.raspberrypi.org/documentation/remote-access/ip-address.md).

More information on Bridged AP mode is provided [in our documentation](https://docs.raspap.com/bridged/).

## Simultaneous AP and Wifi client
RaspAP lets you create an AP with a Wifi client configuration, often called [AP-STA mode](https://docs.raspap.com/ap-sta/). With your system configured in managed mode, enable the AP from the **Advanced** tab of **Configure hotspot** by sliding the **Wifi client AP mode** toggle. Save settings and start the hotspot. The managed mode AP is functional without restart.

**Note:** This option is disabled until you configure your system as a wireless client. For a device operating in [managed mode](https://docs.raspap.com/faq/#headless) without an `eth0` connection, this configuration must be enabled [_before_ a reboot](https://docs.raspap.com/ap-sta/). 

## Manual installation
Detailed manual setup instructions are provided [on our documentation site](https://docs.raspap.com/manual/).

## 802.11ac 5GHz support
RaspAP provides an 802.11ac wireless mode option for supported hardware (currently the RPi 3B+/4 and compatible Orange Pi models) and wireless regulatory domains. See [this](https://docs.raspap.com/ap-basics/#80211ac-5-ghz) for more information.

## Supported operating systems
RaspAP was originally made for Raspbian, but now also installs on the following Debian-based distros.

| Distribution | Release  | Architecture | Support |
|---|:---:|:---:|:---:|
| Raspberry Pi OS | (64-bit) Lite Bookworm	| ARM | Official |
| Raspberry Pi OS | (32-bit) Lite Bookworm | ARM | Official |
| Raspberry Pi OS | (64-bit) Desktop Bookworm | ARM | Official |
| Raspberry Pi OS | (64-bit) Lite Bullseye | ARM | Official |
| Raspberry Pi OS | (32-bit) Lite Bullseye | ARM | Official |
| Armbian | 23.11 (Jammy) | [ARM](https://docs.armbian.com/#supported-socs) | Official |
| Debian  |  Bookworm | ARM / x86_64  | Beta |
| Ubuntu  |  Server 23.04 (Lunar) | ARM / x86_64  | Beta |

<img src="https://github.com/RaspAP/raspap-webgui/assets/229399/6fe62f2d-631a-46c9-8ceb-83ebf0ade6a9" style="width:640px;" />

You are also encouraged to use RaspAP's community-led [Docker container](#docker-support). Please note that "supported" is not a guarantee. If you are able to improve support for your preferred distro, we encourage you to [actively contribute](#how-to-contribute) to the project.

## HTTPS support
The Quick Installer may be used to [generate SSL certificates](https://docs.raspap.com/ssl-quick/) with `mkcert`. The installer automates the manual steps [described here](https://docs.raspap.com/ssl-manual/), including configuring lighttpd with SSL support. 

Simply append the `-c` or `--cert` option to the Quick Installer, like so:

```sh
curl -sL https://install.raspap.com | bash -s -- --cert
```

**Note**: this only installs mkcert and generates an SSL certificate with the input you provide. It does *not* (re)install RaspAP.

More information on SSL certificates and HTTPS support is available [in our documentation](https://docs.raspap.com/ssl/). 

## Docker support
<img src="https://github.com/RaspAP/raspap-webgui/assets/229399/dc40dfc4-e9b8-405f-8ffb-6c5f88482b8e" width="450">

As an alternative to the [Quick installer](#quick-installer), RaspAP may be run in an isolated, portable [Docker container](https://docs.raspap.com/docker/).

See the [RaspAP-docker repo](https://github.com/RaspAP/raspap-docker/) for more information.

## Custom user plugins
RaspAP's integrated `PluginManager` provides a framework for developers to create custom plugins. To facilitate this, a `SamplePlugin` [repository](https://github.com/RaspAP/SamplePlugin) is available to get developers started on the right track. If you'd like to develop your own plugin for RaspAP, see the [documentation](https://docs.raspap.com/custom-plugins/) or get started right away by forking the [SamplePlugin](https://github.com/RaspAP/SamplePlugin).

## Multilingual support
RaspAP uses [GNU Gettext](https://www.gnu.org/software/gettext/) to manage multilingual messages. In order to use RaspAP with one of our supported translations, you must configure a corresponding language package on your RPi. To list languages currently installed on your system, use `locale -a` at the shell prompt. To generate new locales, run `sudo dpkg-reconfigure locales` and select any other desired locales. Details are provided on our [documentation site](https://docs.raspap.com/translations/).

See this list of [supported languages](https://docs.raspap.com/translations/#supported-languages) that are actively maintained by volunteer translators. If your language is not supported, why not [contribute a translation](https://docs.raspap.com/translations/#contributing-to-a-translation)? Contributors will receive credit as the original translators.

## How to contribute
1. Fork the project in your account and create a new branch: `your-great-feature`.
2. Open an issue in the repository describing the feature contribution you'd like to make.
3. Commit changes in your feature branch.
4. Open a pull request and reference the initial issue in the pull request message.

Find out more about our [coding style guidelines and recommended tools](CONTRIBUTING.md). 

## Reporting issues
Please [read this](https://docs.raspap.com/issues/) before reporting a bug.

## Contributors

### Code Contributors
This project exists thanks to all the awesome people who [contribute](CONTRIBUTING.md) their time and expertise.

<a href="https://github.com/raspap/raspap-webgui/graphs/contributors"><img src="https://opencollective.com/raspap/contributors.svg?width=890&button=false" /></a>

### Financial Contributors
Development of RaspAP is made possible thanks to a sponsorware release model. This means that new features are first exclusively released to sponsors as part of [**Insiders**](https://github.com/sponsors/RaspAP).

Learn more about [how sponsorship works](https://docs.raspap.com/insiders/#how-sponsorship-works), and how easy it is to get access to Insiders.

## License
See the [LICENSE](./LICENSE) file.

