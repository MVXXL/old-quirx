import disnake 
from disnake.ext import commands
from disnake import Member

class UserInfo(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.slash_command()
    async def userinfo(self, inter, member: Member = None):
        member = member or inter.author 

        roles = [role.mention for role in member.roles if role.name != "@everyone"]  
        joined_at = member.joined_at.strftime("%Y-%m-%d %H:%M:%S")
        created_at = member.created_at.strftime("%Y-%m-%d %H:%M:%S")

        embed = disnake.Embed(title=f"Информация о {member.display_name}", color=disnake.Color.blue())
        embed.set_thumbnail(url=member.display_avatar.url)
        embed.add_field(name="Имя пользователя", value=member.name, inline=True)
        embed.add_field(name="Дата присоединения", value=joined_at, inline=True)
        embed.add_field(name="Дата создания аккаунта", value=created_at, inline=True)
        embed.add_field(name="Роли", value=" ".join(roles) if roles else "Нет ролей", inline=False)

        await inter.response.send_message(embed=embed)

def setup(bot):
    bot.add_cog(UserInfo(bot))
